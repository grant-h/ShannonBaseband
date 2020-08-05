# Auto-renamer for Shannon baseband firmware
# @author Grant Hernandez (https://github.com/grant-h)
# @category Shannon

# This script was copied from a GHIDRA example script, so its a bit rough

import exceptions
import os
import re

import ghidra.app.script.GhidraScript
#import ghidra.program.model.data.StringDataType as StringDataType
import ghidra.program.model.data.AbstractStringDataType as AbstractStringDataType
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.program.util import CyclomaticComplexity

capital_letter = re.compile("[A-Z]")
c_function = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*')
c_justname = re.compile(r'[a-zA-Z][a-zA-Z0-9]*')
c_function_caps = re.compile(r'^[A-Z_][A-Z0-9_]*$')

class Node:
    def __str__(self):
        raise NotImplementedError("Must sub-class")
    def indentedString(self, depth=0):
        raise NotImplementedError("")
    def __str__(self):
        return self.indentedString(depth=0)

class ReferenceNode(Node):
    def __init__(self, fromAddr, toAddr):
        self.fromAddr = fromAddr
        self.toAddr = toAddr
    def indentedString(self, depth=0):
        raise NotImplementedError("")

class StringNode(ReferenceNode):
    def __init__(self, fromAddr, toAddr, string):
        ReferenceNode.__init__(self, fromAddr, toAddr)
        self.string = string
    def __str__(self):
        return self.indentedString(depth=0)
    def indentedString(self, depth=0):
        string = "%s\n" % ( self.string)
        return string
    def hasString(self):
        return True
    def isFilename(self):
        return False

class FilenameNode(ReferenceNode):
    def __init__(self, fromAddr, toAddr, string):
        ReferenceNode.__init__(self, fromAddr, toAddr)
        self.string = string
    def __str__(self):
        return self.indentedString(depth=0)
    def indentedString(self, depth=0):
        string = "%s\n" % ( self.string)
        return string
    def isFilename(self):
        return True
    def hasString(self):
        return True

class FunctionNode(ReferenceNode):
    def __init__(self, fromAddr, toAddr):
        ReferenceNode.__init__(self, fromAddr, toAddr)
        self.fn = getFunctionContaining(toAddr)
        self.references = []
    def hasString(self):
        for r in self.references:
            if isinstance(r, StringNode) or r.hasString():
                return True
        return False
    def indentedString(self, depth=0):
        string = "%s()\n" % (self.fn.getName())
        for r in self.references:
            if r.hasString():
                string += "%s@%s - %s" % ("   " * (depth+1), r.fromAddr, r.indentedString(depth=depth+1))
        return string

    def predictedName(self):
        string = "%s()\n" % (self.fn.getName())

        name_freq = {}
        file_names = {}
        filename = ""
        filename_parts = []

        for r in self.references:
            if r.hasString() and r.isFilename():
                if r.string not in file_names:
                    file_names[r.string] = 1
                else:
                    file_names[r.string] += 1

        if len(file_names) > 0:
            ranked_filenames = sorted(file_names.items(), key=lambda x: x[1], reverse=True)
            filepath = ranked_filenames[0][0]
            filepath_components = filepath.split("/")
            filename = ".".join(filepath_components[-1].split(".")[:-1])
            filename_parts = list(filter(lambda x: len(x) > 2, c_justname.findall(filename)))

        for r in self.references:
            if r.hasString() and not r.isFilename():
                names = extractLikelyNames(r.string)

                for n in names:
                    if n in name_freq:
                        name_freq[n]["seen"] += 1
                        continue

                    score = 1

                    prefix = n.split("_")[0]

                    # functions usually dont start with underscores
                    if n[0] == "_":
                        score -= 3

                    # ding enums
                    if c_function_caps.match(n):
                        score -= 3

                    # we'd prefer to have a unique filename-like string, but not exactly the filename
                    if filename == n:
                        score -= 1

                    for part in filename_parts:
                        if part.lower() in n:
                            score += 1
                            break

                    name_freq[n] = {"score" : score, "seen" : 1}

        if len(name_freq) == 0:
            # a filename is better than nothing
            if filename != "":
                return filename
            return None

        ranked_names = sorted(name_freq.items(), key=lambda x: (x[1]["score"], x[1]["seen"]), reverse=True)
        top_one = ranked_names[0]
        ranked_names = dict(ranked_names)

        tied = []

        for k,v in ranked_names.items():
            if v["score"] == top_one[1]["score"]:
                tied += [(k, v)]

        top_one_seen = tied[-1]
        needs_prefix = False

        #print(ranked_names)
        #print(filename, tied, top_one_seen)

        if len(tied) == 1:
            guess = tied[0][0]
            needs_prefix = True
            com = os.path.commonprefix([guess.lower(), filename.lower()])
            needs_prefix = len(com) < len(filename)
        else:
            better = []
            for k,v in tied:
                com = os.path.commonprefix([k.lower(), filename.lower()])
                if len(com) >= 2:
                    better += [(k, v, len(com))]

            #print("BETTER", better)

            # just choose the most "unique" string
            if len(better) == 0:
                guess = sorted(tied, key=lambda x: (x[1]["seen"]*len(x[0])), reverse=True)
                guess = guess[0][0]
                needs_prefix = True
            else:

                better = sorted(better, key=lambda x: (x[2], -x[1]["seen"]), reverse=True)
                guess = better[0][0]

        if needs_prefix:
            if filename == "":
                return None
            return "%s__%s" % (filename, guess)
        else:
            return "%s" % (guess)

    def getAddresses(self):
        return self.fn.getBody().getAddresses(True)
    def addReference(self, reference):
        rlist = []
        if not isinstance(reference, list):
            rlist.append(reference)
        for r in rlist:
            if not isinstance(r, ReferenceNode):
                raise ValueError("Must only add ReferenceNode type")
            else:
                self.references.append(r)
    def getName(self):
        if self.fn is not None:
            return self.fn.getName()
        else:
            return "fun_%s" % (self.toAddr)
    def process(self, processed=[]):
        if self.fn is None:
            return processed
        #print("Processing %s -> %s" % (str(self.fromAddr), str(self.toAddr)))
        if self.getName() in processed:
            return processed
        addresses = self.getAddresses()
        while addresses.hasNext():
            #for a in addresses:
            a = addresses.next()
            insn = getInstructionAt(a)
            if insn is not None:
                refs = getReferences(insn)
                for r in refs:
                    self.addReference(r)
        
        processed.append(self.getName())
        #for r in self.references:
            #if isinstance(r, FunctionNode):
            #    processed = r.process(processed=processed)
        return processed
    
class FunctionNotFoundException(exceptions.Exception):
    pass   

def getStringAtAddr(addr):
    """Get string at an address, if present"""
    data = getDataAt(addr)
    if data is not None:
        dt = data.getDataType()
        if isinstance(dt, AbstractStringDataType):
            return str(data.getValue())
    return None

def getTraceEntryAtAddr(addr):
    """Get TraceEntry at an address, if present"""
    data = getDataAt(addr)
    if data is not None:
        dt = data.getDataType()

        if dt.getName() == "TraceEntry":
            return data
    return None

def getStringReferences(insn):
    """Get strings referenced in any/all operands of an instruction, if present"""
    numOperands = insn.getNumOperands()
    found = []
    for i in range(numOperands):
        opRefs = insn.getOperandReferences(i)
        for o in opRefs:
            if o.getReferenceType().isData():
                string = getStringAtAddr(o.getToAddress())
                if string is not None:
                    if string.startswith("../"):
                        found.append( FilenameNode(insn.getMinAddress(), o.getToAddress(), string) )
                    else:
                        found.append( StringNode(insn.getMinAddress(), o.getToAddress(), string) )
    return found

def extractLikelyNames(ref):
    function_names = c_function.findall(ref)
    function_names = list(filter(lambda x: len(x) > 3, function_names))

    return function_names

def getTraceEntryReferences(insn):
    """Get TraceEntries referenced in any/all operands of an instruction, if present"""
    numOperands = insn.getNumOperands()
    found = []

    for i in range(numOperands):
        opRefs = insn.getOperandReferences(i)
        for o in opRefs:
            if o.getReferenceType().isData():
                te = getTraceEntryAtAddr(o.getToAddress())
                if te is not None:
                    file_p = te.getComponent(6)
                    file_data = getStringAtAddr(file_p.getValue())

                    message_p = te.getComponent(4)
                    message_data = getStringAtAddr(message_p.getValue())

                    if message_data is not None:
                        found.append( StringNode(insn.getMinAddress(), o.getToAddress(), str(message_data)) )

                    if file_data is not None:
                        found.append( FilenameNode(insn.getMinAddress(), o.getToAddress(), str(file_data)) )

    return found

def getFunctionReferences(insn):
    """Return a list of functions referenced in the given instruction"""
    numOperands = insn.getNumOperands()
    lst = []
    for i in range(numOperands):
        opRefs = insn.getOperandReferences(i)
        for o in opRefs:
            if o.getReferenceType().isCall():
                lst.append( FunctionNode(insn.getMinAddress(), o.getToAddress()) )
    return lst

def getReferences(insn):
    refs = []
    refs += getStringReferences(insn)
    refs += getTraceEntryReferences(insn)
    #refs += getFunctionReferences(insn)
    return refs


def fromSelection():
    bigfunc = getFunctionContaining(currentAddress)
    if bigfunc is None:
        print("Please place the cursor within a function!")
    else:
        AddrSetView = bigfunc.getBody()
        func = FunctionNode(None, AddrSetView.getMinAddress())
        func.process()

        print(str(func.indentedString()))
        print(func.predictedName())
        #findStrings(func)

def fixupSmallFunctions():
    mgr = currentProgram.getFunctionManager()

    monitor.setIndeterminate(False)
    monitor.initialize(mgr.getFunctionCount())
    monitor.setCancelEnabled(True)

    monitor.setProgress(0)
    monitor.setMessage("Fixup functions...")

    successful = 0

    for function in mgr.getFunctions(True):
        if monitor.isCancelled():
            break

        body = function.getBody()
        if body.getNumAddresses() == 1:
            cmd = CreateFunctionCmd(body.getMinAddress())
            print("Re-creating small function %s" % (function.getName()))
            result = cmd.applyTo(currentProgram)

            if result:
                successful += 1

        monitor.incrementProgress(1)

    print("Fixed up %d functions (%.2f%%)" % (successful, float(successful)/mgr.getFunctionCount()*100.0))

def getCyclomaticComplexity():
    mgr = currentProgram.getFunctionManager()

    monitor.setIndeterminate(False)
    monitor.initialize(mgr.getFunctionCount())
    monitor.setCancelEnabled(True)

    monitor.setProgress(0)
    monitor.setMessage("Cyclomatic complexity...")

    successful = 0

    cyc = CyclomaticComplexity()

    complex_list = []
    for function in mgr.getFunctions(True):
        if monitor.isCancelled():
            break

	name = function.getName()

        if "decode" not in name.lower():
            monitor.incrementProgress(1)
            continue

        res = cyc.calculateCyclomaticComplexity(function, monitor)
        complex_list += [(name, res)]

        monitor.incrementProgress(1)
    
    complex_list = sorted(complex_list, key=lambda x: x[1], reverse=True)

    for name, complexity in complex_list:
        print("%s: %s" % (name, complexity))


def processAll():
    mgr = currentProgram.getFunctionManager()

    monitor.setIndeterminate(False)
    monitor.initialize(mgr.getFunctionCount())
    monitor.setCancelEnabled(True)

    monitor.setProgress(0)
    monitor.setMessage("Renaming functions...")

    i = 0
    successful = 0

    for function in mgr.getFunctions(True):
        if monitor.isCancelled():
            break

        if not function.getName().startswith("FUN_"):
            monitor.incrementProgress(1)
            continue

        AddrSetView = function.getBody()
        func = FunctionNode(None, AddrSetView.getMinAddress())
        func.process()

        name = func.predictedName()

        if name is not None:
            function.setName(name, SourceType.USER_DEFINED)
            successful += 1

        i += 1

        monitor.incrementProgress(1)

    print("Renamed %d functions (%.2f%%)" % (successful, float(successful)/mgr.getFunctionCount()*100.0))

def main():
    processAll()

    # uncomment the below depending on what you are interested in doing
    #getCyclomaticComplexity() # get a list of complex decoder functions :)
    #fromSelection() # rename the function your cursor is in (good for testing renaming heuristics)
    #fixupSmallFunctions() # fixes single byte functions for export via BinDiff (weird binexport/GHIDRA error?)
    print("Done!")

if __name__ == "__main__":
    main()

