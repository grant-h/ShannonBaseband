# Fixup call sites to a previously non-returning function.
# Auto-renamer for Shannon baseband firmware
# @author Grant Hernandez (https://github.com/grant-h)
# @category Shannon
## Copyright (c) 2023, Grant Hernandez
## SPDX-License-Identifier: MIT

# This is super hacky and only needed if you borked your import and are left with a bunch of undisassembled blocks due to false positive non-returning functions
# Included in the Shannon release for demonstrating some interesting uses of the API (disassembly, flow overrides)

import time
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.cmd.disassemble import ArmDisassembleCommand, SetFlowOverrideCmd
from ghidra.program.model.listing import FlowOverride
from ghidra.program.model.symbol import FlowType

class SetFlowOverrideCmdWatch(SetFlowOverrideCmd):
    def __init__(self, addr, foverride):
        self.addr = addr
        SetFlowOverrideCmd.__init__(self, addr, foverride)

    def taskCompleted(self):
        print("Completed %s" % self.addr)

def main():
    target_function = getFunctionContaining(currentAddress)
    if target_function is None:
        print("Please place the cursor within a function!")
        return

    rm = currentProgram.getReferenceManager()
    fapi = FlatProgramAPI(currentProgram)
    target_address = target_function.getBody().getMinAddress()

    references = []

    for i, ref in enumerate(rm.getReferencesTo(target_address)):
        references += [ref]

    maximum = len(references)
    monitor.setIndeterminate(False)
    monitor.initialize(maximum)
    monitor.setCancelEnabled(True)

    monitor.setProgress(0)
    monitor.setMessage("Fixing up %s references..." % target_function.getName())

    references = sorted(references, key=lambda x: x.getFromAddress())

    edit_count = 0

    for cur, ref in enumerate(references):
        if cur > 1 and cur % 1000 == 0 and edit_count > 100:
            # let auto analysis catch up
            time.sleep(10.0)
            edit_count = 0

        if target_function.hasNoReturn():
            print("Function has gone into no-return!")
            break

        monitor.setProgress(cur + 1)

        caddr = ref.getFromAddress()

        insn = getInstructionAt(caddr)
        insn_next = insn.getNext()
        foverride = insn.getFlowOverride()

        op = insn.toString().split(" ")[0]
        op_next = insn_next.toString().split(" ")[0]

        if not op.startswith("bl"):
            print("[%d/%d] [%s] skipping non bl/blx" % (cur + 1, maximum, caddr))
            continue

        # if insn_next.getFlowType() != FlowType.FALL_THROUGH:
            #print("[%d/%d] [%s] skipping %s" % (cur+1, maximum, caddr, insn_next.getFlowType()))
            # continue

        # if op_next == "b":
        #	iter = rm.getReferencesTo(insn_next.getAddress())
        #	if isinstance(iter, ghidra.program.database.references.EmptyMemReferenceIterator):
            #	print("Skipping badness @ %s" % caddr)
            #	#fapi.clearListing(caddr, caddr.add(4))
            # break
            # else:
            #print("Potential badness @ %s" % caddr)

        if foverride == FlowOverride.CALL_RETURN:
            print("[%d/%d] [%s] fixing up" % (cur + 1, maximum, caddr))

            pctx = insn.getInstructionContext().getProcessorContext()
            tmode_reg = pctx.getRegister("TMode")
            tmode = pctx.getRegisterValue(tmode_reg)
            tmode = tmode.getUnsignedValue()

            cmd = ArmDisassembleCommand(caddr.add(4), None, tmode == 1)
            fcmd = SetFlowOverrideCmd(caddr, FlowOverride.NONE)

            # slow path
            # if op_next == "b":
            #	print("SLOW")
            #	fapi.clearListing(caddr, caddr.add(insn.getLength()))
            if not cmd.applyTo(currentProgram):
                print("Failed to submit disassembly cmd for %s" % caddr)
            	continue

            # else:
            if not fcmd.applyTo(currentProgram):
                print("Failed to submit flow override cmd for %s" % caddr)
                continue

            edit_count += 1

            # if cur > 500:
            # time.sleep(2.0)
            # time.sleep(0.5)

            # insn.setFlowOverride(FlowOverride.NONE)
        elif foverride == FlowOverride.NONE:
            print("[%d/%d] [%s] skipping, no override" % (cur + 1, maximum, caddr))
        else:
            print("[%d/%d] [%s] unexpected override %s" %
                  (cur + 1, maximum, caddr, foverride))

if __name__ == "__main__":
    main()
