function status = capture_pcode_trace(pfilePath, tracePath)
%CAPTURE_PCODE_TRACE Decode a P-file into a PCTR record trace.
%   STATUS = CAPTURE_PCODE_TRACE(PFILEPATH, TRACEPATH) asks MATLAB to parse
%   PFILEPATH without executing its function body and saves the resulting
%   decoded AST/PVM records to TRACEPATH.

arguments
    pfilePath (1, 1) string
    tracePath (1, 1) string
end

[pfileDirectory, functionName, extension] = fileparts(pfilePath);
if extension ~= ".p"
    error('pcode:capture:NotPFile', 'Input must have a .p extension.');
end
if pfileDirectory == ""
    pfileDirectory = string(pwd);
end
if ~isfile(fullfile(pfileDirectory, functionName + extension))
    error('pcode:capture:MissingInput', 'P-file not found: %s', pfilePath);
end

toolDirectory = string(fileparts(mfilename('fullpath')));
savedPath = path;
pathCleanup = onCleanup(@() path(savedPath));
addpath(toolDirectory, '-begin');
addpath(pfileDirectory, '-begin');

pcode_record_trace('start');
hookCleanup = onCleanup(@() pcode_record_trace('stop'));
pcode_record_trace('clear');
clear(char(functionName));
nargin(char(functionName));
pcode_record_trace('save', char(tracePath));
status = pcode_record_trace('status');

if status.captureFailed
    error('pcode:capture:Failed', 'MATLAB parsed the file, but record capture failed.');
end
end
