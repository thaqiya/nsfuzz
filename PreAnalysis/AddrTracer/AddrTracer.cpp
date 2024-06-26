#include <iostream>
#include <fstream>
#include <string>
#include "pin.H"

using namespace std;

KNOB<string> KnobTraceFile(KNOB_MODE_WRITEONCE, "pintool",
                           "o", "trace.out", "specify trace file name");

// static ofstream *trace_file = 0;
static FILE *trace_file;
static ADDRINT main_addr;     // the start address of main
static ADDRINT main_ret_addr; // the ret address of main

bool main_start = false;

INT32 Usage()
{
    cerr << "This Pintool prints the IPs of every instruction executed with function name\n"
            "Usage: \n";
    cerr << "pin -t pintool <-o your_trace_file> -- binary\n"
            "\n";
    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;
    return -1;
}


VOID printip(ADDRINT ins_addr, string *rtn_name) {

    if (ins_addr == main_addr) main_start = true;

    if (!main_start) return;

    // *trace_file << "0x" << hex << ins_addr << setw(20);
    // *trace_file << rtn_name->c_str() << "\t\t";
    // *trace_file << ins_dis->c_str() << endl;
    fprintf(trace_file, "0x%-20lx\t\t", ins_addr);
    fprintf(trace_file, "%-20s\n", rtn_name->c_str());
    // fprintf(trace_file, "%-20s\n", ins_dis->c_str());

    if (ins_addr == main_ret_addr) main_start = false;
}

VOID ImageLoad(IMG img, VOID *v) {
    // only trace the inst within main executable (eliminate shared libraries)
    if (IMG_IsMainExecutable(img)) {

        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {

            if (SEC_Name(sec) == ".text") {

                for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {

                    string rtn_name = RTN_Name(rtn);
                    bool is_main = false;
                    // cout << rtn_name << endl;

                    RTN_Open(rtn);

                    ADDRINT ins_addr = INS_Address(RTN_InsHead(rtn));

                    if (rtn_name == "main") {
                        is_main = true;
                        main_addr = ins_addr;
                    }

                    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)){
                        ins_addr = INS_Address(ins);                
                        // string ins_dis = INS_Disassemble(ins);
                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_UINT32, ins_addr, IARG_PTR, new string(rtn_name), IARG_END);
                    }

                    if (is_main) 
                        main_ret_addr = ins_addr;

                    RTN_Close(rtn);
                }

                break;
            }
        }
    }
}

VOID Fini(INT32 code, VOID *v) {
    std::cout << "Finished" << std::endl;

    // *trace_file << "# $eof" << endl;
    // fprintf(trace_file, "# $eof\n");

    // trace_file->close();
    fclose(trace_file);
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();

    if ( PIN_Init(argc, argv) )
        return Usage();

    string file_name = KnobTraceFile.Value();

    trace_file = fopen(file_name.c_str(), "w");

    // trace_file = new std::ofstream(file_name.c_str());

    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
}
