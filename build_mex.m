function build_mex()
%BUILD_MEX Build the Windows x64 decoded-record tracing MEX.

root = fileparts(mfilename('fullpath'));
source = fullfile(root, 'pcode_record_trace.cpp');
mex('-outdir', root, source);
end
