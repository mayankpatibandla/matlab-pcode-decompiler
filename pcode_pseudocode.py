#!/usr/bin/env python3
"""Best-effort MATLAB-like listing from a captured R2025a PVM record trace.

This is intentionally tolerant: unsupported AST records are retained as tagged
placeholders instead of aborting the listing.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
from typing import Any

from analyze_record_trace import PermutationEvent, Record, read_trace_with_permutations


@dataclasses.dataclass
class Node:
    kind: str
    text: str
    children: list["Node"] = dataclasses.field(default_factory=list)
    line: int | None = None
    end_line: int | None = None


@dataclasses.dataclass
class Raw:
    text: str


@dataclasses.dataclass
class Sequence:
    items: list[Node]


@dataclasses.dataclass
class OptionalNode:
    value: Any


@dataclasses.dataclass
class Signature:
    name: str
    outputs: list[str]
    inputs: list[str]
    line: int | None = None


BINARY_OPERATORS = {
    0: "+", 1: "+", 2: "-", 3: "*", 4: "/", 5: "\\", 6: "^",
    7: ".*", 8: "./", 9: ".\\", 10: "==", 11: "<=", 12: "<",
    13: ">=", 14: ">", 15: "==", 16: "~=", 17: "&&", 18: "&",
    19: "||", 20: "|", 21: ":",
}
UNARY_OPERATORS = {0: "+", 1: "'", 2: "-", 3: ".'", 5: "~"}


def matlab_char(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def matlab_string(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


class Decoder:
    def __init__(self, permutations: dict[int, PermutationEvent]) -> None:
        self.permutations = permutations
        self.strings: dict[int, str] = {}
        self.pending_string = ""
        self.stack: list[Any] = []
        self.statements: list[Node] = []
        self.ends: list[Node] = []
        self.signatures: list[Signature] = []
        self.current_signature: Signature | None = None
        self.unknown_counts: dict[int, int] = {}

    def pop(self, default: Any = None) -> Any:
        return self.stack.pop() if self.stack else default

    def pop_node(self, default_text: str = "<?>" ) -> Node:
        value = self.pop()
        if isinstance(value, OptionalNode):
            value = value.value
        if isinstance(value, Node):
            return value
        if isinstance(value, Raw):
            return Node("name", value.text)
        return Node("unknown", default_text)

    def pop_sequence(self) -> Sequence:
        value = self.pop()
        if isinstance(value, OptionalNode):
            value = value.value
        if isinstance(value, Sequence):
            return value
        if isinstance(value, Node):
            return Sequence([value])
        return Sequence([])

    def pop_many(self, count: int, record_index: int | None = None) -> list[Any]:
        if count <= 0:
            return []
        values = [self.pop() for _ in range(min(count, len(self.stack)))]
        values.reverse()
        event = self.permutations.get(record_index) if record_index is not None else None
        if event and len(values) == count and len(event.placements) == count:
            ordered: list[Any] = [None] * count
            for source, destination in event.placements:
                if source < count and destination < count:
                    ordered[destination] = values[source]
            if all(item is not None for item in ordered):
                values = ordered
        return values

    def raw_from_operand(self, value: int) -> str:
        if value == 0 and self.stack and isinstance(self.stack[-1], Raw):
            return self.pop().text
        return self.strings.get(value, f"<str#{value}>")

    def add_statement(self, node: Node) -> None:
        self.statements.append(node)
        self.stack.append(node)

    def apply_position(self, value: int) -> None:
        if not self.stack:
            return
        target = self.stack[-1]
        if isinstance(target, OptionalNode):
            target = target.value
        if not isinstance(target, Node):
            return
        field = value & 3
        position = value >> 2
        if field == 0:
            target.line = position
        elif field in (1, 2):
            target.end_line = position

    def process(self, record: Record) -> None:
        t, value = record.type, record.value
        if t == 4:
            self.pending_string = record.payload.decode("utf-8", errors="replace")
        elif t == 5:
            self.strings[value] = self.pending_string
            self.stack.append(Raw(self.pending_string))
        elif t == 6:
            self.stack.append(Raw(self.strings.get(value, f"<str#{value}>")))
        elif t == 66:
            raw = self.pop()
            text = raw.text if isinstance(raw, Raw) else "<?>"
            self.stack.append(Node("name", text))
        elif t == 97:
            self.apply_position(value)
        elif t == 77:
            self.stack.append(Node("number", self.raw_from_operand(value)))
        elif t == 45:
            self.stack.append(Node("char", matlab_char(self.raw_from_operand(value))))
        elif t == 90:
            self.stack.append(Node("string", matlab_string(self.raw_from_operand(value))))
        elif t == 70:
            node = self.pop_node()
            node.kind = "input"
            self.stack.append(node)
        elif t == 19:
            items = [item for item in self.pop_many(value, record.index) if isinstance(item, Node)]
            self.stack.append(("outputs", items))
        elif t == 20:
            inputs = [item for item in self.pop_many(value, record.index) if isinstance(item, Node)]
            name_node = self.pop_node("<function>")
            output_value = self.pop()
            outputs = output_value[1] if isinstance(output_value, tuple) and output_value[0] == "outputs" else []
            signature = Signature(name_node.text, [item.text for item in outputs],
                                  [item.text for item in inputs], name_node.line)
            self.current_signature = signature
            self.signatures.append(signature)
            self.stack.append(signature)
        elif t == 11:
            # Discard the compiler's implicit `ans` declaration and begin body records.
            self.stack = [self.current_signature] if self.current_signature else []
        elif t == 39:
            right, left = self.pop_node(), self.pop_node()
            op = BINARY_OPERATORS.get(value, f"<op{value}>")
            self.stack.append(Node("binary", f"({left.text} {op} {right.text})", [left, right]))
        elif t == 93:
            operand = self.pop_node()
            op = UNARY_OPERATORS.get(value, f"<unary{value}>")
            self.stack.append(Node("unary", f"({op}{operand.text})", [operand]))
        elif t == 80:
            operand = self.pop_node()
            self.stack.append(Node("paren", f"({operand.text})", [operand]))
        elif t == 36:
            right, left = self.pop_node(), self.pop_node()
            self.add_statement(Node("assignment", f"{left.text} = {right.text};", [left, right]))
        elif t == 18:
            items = [item for item in self.pop_many(value, record.index) if isinstance(item, Node)]
            self.stack.append(Sequence(items))
        elif t == 79:
            arguments = self.pop_sequence()
            callee = self.pop_node()
            text = f"{callee.text}({', '.join(item.text for item in arguments.items)})"
            self.stack.append(Node("call", text, [callee, *arguments.items]))
        elif t == 88:
            row = self.pop_sequence()
            self.stack.append(Node("row", ", ".join(item.text for item in row.items), row.items))
        elif t == 24:
            rows = [item for item in self.pop_many(value, record.index) if isinstance(item, Node)]
            self.stack.append(Sequence(rows))
        elif t in (71, 44):
            rows = self.pop_sequence()
            left, right = ("[", "]") if t == 71 else ("{", "}")
            self.stack.append(Node("matrix" if t == 71 else "cell",
                                   left + "; ".join(row.text for row in rows.items) + right,
                                   rows.items))
        elif t == 62:
            field = self.pop_node()
            field.kind = "field"
            self.stack.append(field)
        elif t == 51:
            field, base = self.pop_node(), self.pop_node()
            self.stack.append(Node("field_access", f"{base.text}.{field.text}", [base, field]))
        elif t == 49:
            arguments = self.pop_sequence()
            command = self.pop_node("<command>")
            suffix = " ".join(item.text.strip("'") for item in arguments.items)
            self.stack.append(Node("command", command.text + (" " + suffix if suffix else ""),
                                   [command, *arguments.items]))
        elif t == 61:
            expression = self.pop_node()
            implicit_ans = self.pop_node("ans")
            self.stack.append(Node("expression", expression.text, [implicit_ans, expression]))
        elif t == 48:
            stop = self.pop_node()
            middle = self.pop()
            start = self.pop_node()
            if isinstance(middle, OptionalNode):
                middle = middle.value
            if isinstance(middle, Node):
                text = f"{start.text}:{middle.text}:{stop.text}"
                children = [start, middle, stop]
            else:
                text = f"{start.text}:{stop.text}"
                children = [start, stop]
            self.stack.append(Node("colon", text, children))
        elif t == 55:
            node = Node("end", "end")
            self.ends.append(node)
            self.statements.append(node)
            self.stack.append(node)
        elif t == 25:
            items = [item for item in self.pop_many(value, record.index) if isinstance(item, Node)]
            self.stack.append(Sequence(items))
        elif t == 54:
            body, condition = self.pop_sequence(), self.pop_node()
            node = Node("elseif", f"elseif {condition.text}", [condition, *body.items])
            self.statements.append(node)
            self.stack.append(node)
        elif t == 53:
            body = self.pop_sequence()
            node = Node("else", "else", body.items)
            self.statements.append(node)
            self.stack.append(node)
        elif t == 42:
            body, expression = self.pop_sequence(), self.pop_node()
            node = Node("case", f"case {expression.text}", [expression, *body.items])
            self.statements.append(node)
            self.stack.append(node)
        elif t == 78:
            body = self.pop_sequence()
            node = Node("otherwise", "otherwise", body.items)
            self.statements.append(node)
            self.stack.append(node)
        elif t == 43:
            body = self.pop_sequence()
            name = self.pop_node()
            node = Node("catch", f"catch {name.text}", [name, *body.items])
            self.statements.append(node)
            self.stack.append(node)
        elif t in (13, 14, 15, 22):
            self.stack.append(Sequence(self.pop_many(value, record.index)))
        elif t == 96:
            if value == 0:
                self.stack.append(OptionalNode(None))
            else:
                self.stack.append(OptionalNode(self.pop()))
        elif t == 63:
            body, iterable, variable = self.pop_sequence(), self.pop_node(), self.pop_node()
            self.add_statement(Node("for", f"for {variable.text} = {iterable.text}",
                                    [variable, iterable, *body.items]))
        elif t == 95:
            body, condition = self.pop_sequence(), self.pop_node()
            self.add_statement(Node("while", f"while {condition.text}", [condition, *body.items]))
        elif t == 67:
            optional_else = self.pop()
            elseif_items = self.pop_sequence()
            body = self.pop_sequence()
            condition = self.pop_node()
            extra: list[Node] = []
            if isinstance(optional_else, OptionalNode) and isinstance(optional_else.value, Node):
                extra.append(optional_else.value)
            self.add_statement(Node("if", f"if {condition.text}",
                                    [condition, *body.items, *elseif_items.items, *extra]))
        elif t == 91:
            optional_otherwise = self.pop()
            cases = self.pop_sequence()
            expression = self.pop_node()
            extra: list[Node] = []
            if isinstance(optional_otherwise, OptionalNode) and isinstance(optional_otherwise.value, Node):
                extra.append(optional_otherwise.value)
            self.add_statement(Node("switch", f"switch {expression.text}",
                                    [expression, *cases.items, *extra]))
        elif t == 92:
            optional_catches = self.pop()
            body = self.pop_sequence()
            extra: list[Node] = []
            if isinstance(optional_catches, OptionalNode) and isinstance(optional_catches.value, Node):
                extra.append(optional_catches.value)
            self.add_statement(Node("try", "try", [*body.items, *extra]))
        elif t == 83:
            expression = self.pop_node()
            self.add_statement(Node("expression_statement", expression.text + ";", [expression]))
        elif t == 64:
            # Function-body wrapper. Preserve the current stack for local functions.
            pass
        elif t in (1, 84):
            pass
        else:
            self.unknown_counts[t] = self.unknown_counts.get(t, 0) + 1

    def run(self, records: list[Record]) -> None:
        for record in records:
            self.process(record)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument(
        "--executable",
        action="store_true",
        help="emit MATLAB code at recovered source-line positions instead of a commented listing",
    )
    args = parser.parse_args()

    records, permutations = read_trace_with_permutations(args.trace)
    decoder = Decoder(permutations)
    decoder.run(records)
    def signature_text(signature: Signature) -> str:
        outputs = ""
        if len(signature.outputs) == 1:
            outputs = signature.outputs[0] + " = "
        elif signature.outputs:
            outputs = "[" + ", ".join(signature.outputs) + "] = "
        return f"function {outputs}{signature.name}({', '.join(signature.inputs)})"

    positioned = [node for node in decoder.statements if node.line is not None]
    events: list[tuple[int, int, str]] = []
    for signature in decoder.signatures:
        if signature.line is not None:
            events.append((signature.line, 0, signature_text(signature)))
    for node in positioned:
        priority = 9 if node.kind == "end" else 1
        events.append((node.line or 0, priority, node.text))
    events.sort()

    unpositioned_signatures = [item for item in decoder.signatures if item.line is None]
    unpositioned = [node for node in decoder.statements if node.line is None]
    if args.executable:
        if decoder.unknown_counts or unpositioned_signatures or unpositioned:
            raise SystemExit(
                "executable output requires every record and source position to be resolved"
            )
        source_lines = [""] * max(line_number for line_number, _, _ in events)
        for line_number, _, event_text in events:
            index = line_number - 1
            if source_lines[index]:
                source_lines[index] += " " + event_text
            else:
                source_lines[index] = event_text
        text = "\n".join(source_lines) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8", newline="\n")
        else:
            print(text, end="")
        return

    lines: list[str] = []
    lines.append("% Best-effort reconstruction from decoded MATLAB PVM records.")
    for line_number, _, event_text in events:
        lines.append(f"% line {line_number:4d}: {event_text}")
    if unpositioned_signatures:
        lines.append("")
        lines.append("% Function signatures whose source position was not recovered:")
        for signature in unpositioned_signatures:
            lines.append("%   " + signature_text(signature))
    if unpositioned:
        lines.append("")
        lines.append("% Statements whose source position was not recovered:")
        for node in unpositioned:
            lines.append(f"%   {node.text}")
    if decoder.unknown_counts:
        lines.append("")
        lines.append("% Unhandled record types: " + ", ".join(
            f"{key}({value})" for key, value in sorted(decoder.unknown_counts.items())))
    text = "\n".join(lines) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()

