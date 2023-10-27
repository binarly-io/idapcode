import traceback
from typing import Dict, List, Optional

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_lines
import ida_name
import idaapi
from pypcode import Arch, Context, PcodePrettyPrinter

NAME = "IDA P-Code"
AUTHOR = "https://github.com/yeggor"

VERSION = "0.0.1"
HELP_MSG = "Get the P-Code for the current function"
COMMENT_MSG = HELP_MSG
WANTED_KEY = "Ctrl+Alt+S"

DEBUG = False


# -----------------------------------------------------------------------
class FuncPcode:
    """Helper class for getting p-code for a function"""

    def __init__(self, addr: int) -> None:
        self._addr: int = addr
        self._func_pcode: Optional[List[str]] = None
        self._func_name: Optional[str] = None
        self._inf = idaapi.get_inf_structure()

        # adopted from
        # https://github.com/cseagle/blc/blob/b1447562a3598fd411224dfc24b970cf53ca7c94/plugin.cc#L516
        self._proc_map: Dict[Any] = dict()
        self._proc_map[idaapi.PLFM_6502] = "6502"
        self._proc_map[idaapi.PLFM_68K] = "68000"
        self._proc_map[idaapi.PLFM_6800] = "6805"
        self._proc_map[idaapi.PLFM_8051] = "8051"
        self._proc_map[idaapi.PLFM_ARM] = "ARM"
        self._proc_map[idaapi.PLFM_AVR] = "avr8"
        self._proc_map[idaapi.PLFM_CR16] = "CR16"
        self._proc_map[idaapi.PLFM_DALVIK] = "Dalvik"
        self._proc_map[idaapi.PLFM_JAVA] = "JVM"
        self._proc_map[idaapi.PLFM_MIPS] = "MIPS"
        self._proc_map[idaapi.PLFM_HPPA] = "pa-risc"
        self._proc_map[idaapi.PLFM_PIC] = "PIC"
        self._proc_map[idaapi.PLFM_PPC] = "PowerPC"
        self._proc_map[idaapi.PLFM_SPARC] = "sparc"
        self._proc_map[idaapi.PLFM_MSP430] = "TI_MSP430"
        self._proc_map[idaapi.PLFM_TRICORE] = "tricore"
        self._proc_map[idaapi.PLFM_386] = "x86"
        self._proc_map[idaapi.PLFM_Z80] = "Z80"

    def _inf_is_64bit(self) -> bool:
        return self._inf.is_64bit()

    def _inf_is_32bit(self) -> bool:
        return self._inf.is_32bit()

    def _get_app_bittness(self) -> int:
        if self._inf_is_64bit():
            return 64
        if self._inf_is_32bit():
            return 32
        return 16

    def _inf_is_be(self) -> bool:
        return self._inf.is_be()

    def _get_proc_id(self) -> int:
        return idaapi.ph_get_id()

    def _get_proc(self) -> Optional[str]:
        proc_id = self._get_proc_id()
        if proc_id not in self._proc_map:
            return None
        return self._proc_map[proc_id]

    def _get_endian(self) -> str:
        if self._inf_is_be():
            return "BE"
        return "LE"

    def _get_sleigh_id(self) -> Optional[str]:
        """Get sleigh language id string"""

        proc = self._get_proc()
        if proc is None:
            return None
        endian = self._get_endian()

        # adopted from
        # https://github.com/cseagle/blc/blob/b1447562a3598fd411224dfc24b970cf53ca7c94/plugin.cc#L637
        sleigh = f"{proc}:{endian}"
        proc_id = self._get_proc_id()
        if proc_id == idaapi.PLFM_6502:
            return f"{sleigh}:16:default"
        elif proc_id == idaapi.PLFM_68K:
            return f"{sleigh}:32:default"
        elif proc_id == idaapi.PLFM_6800:
            return f"{sleigh}:8:default"
        elif proc_id == idaapi.PLFM_8051:
            return f"{sleigh}:16:default"
        elif proc_id == idaapi.PLFM_ARM:
            if self._inf_is_64bit():
                return f"AARCH64:{endian}:64:v8A"
            return f"{sleigh}:32:v7"
        elif proc_id == idaapi.PLFM_AVR:
            if self._get_app_bittness() == 32:
                return f"avr32:{endian}:32:default"
            if self._get_app_bittness() == 16:
                return f"{sleigh}:16:default"
            return sleigh
        elif proc_id == idaapi.PLFM_CR16:
            return f"{sleigh}:16:default"
        elif proc_id == idaapi.PLFM_DALVIK:
            return f"{sleigh}:32:default"
        elif proc_id == idaapi.PLFM_JAVA:
            return f"{sleigh}:32:default"
        elif proc_id == idaapi.PLFM_MIPS:
            abi = idaapi.get_abi_name()
            if abi and ("n32" in abi):
                return f"{sleigh}:64:64-32addr"
            if self._inf_is_64bit():
                return f"{sleigh}:64:default"
            if self._inf_is_32bit():
                return f"{sleigh}:32:default"
            return sleigh
        elif proc_id == idaapi.PLFM_HPPA:
            return f"{sleigh}:32:default"
        elif proc_id == idaapi.PLFM_PIC:
            return sleigh
        elif proc_id == idaapi.PLFM_PPC:
            abi = idaapi.get_abi_name()
            if abi and ("xbox" in abi):
                return f"{sleigh}:64:A2ALT-32addr"
            if self._inf_is_64bit():
                return f"{sleigh}:64:default"
            if self._inf_is_32bit():
                return f"{sleigh}:32:default"
            return sleigh
        elif proc_id == idaapi.PLFM_SPARC:
            if self._inf_is_64bit():
                return f"{sleigh}:64:default"
            if self._inf_is_32bit():
                return f"{sleigh}:32:default"
            return sleigh
        elif proc_id == idaapi.PLFM_MSP430:
            return f"{sleigh}:16:default"
        elif proc_id == idaapi.PLFM_TRICORE:
            return f"{sleigh}:32:default"
        elif proc_id == idaapi.PLFM_386:
            bittness = self._get_app_bittness()
            sleigh += f":{str(bittness)}"
            if bittness == 16:
                return f"{sleigh}:Real Mode"
            return f"{sleigh}:default"
        elif proc_id == idaapi.PLFM_Z80:
            return sleigh
        return None

    def _get_func_name(self) -> str:
        """Get function name"""
        f = ida_funcs.get_func(self._addr)
        if f is None:
            return "unknown"
        return ida_name.get_name(f.start_ea)

    def _get_func_bytes(self) -> bytes:
        """Get function bytes"""
        f = ida_funcs.get_func(self._addr)
        if f is None:
            return bytes()
        return ida_bytes.get_bytes(f.start_ea, f.end_ea - f.start_ea)

    def _get_pcode(self) -> list:
        """Get P-Code lines"""
        code = self._get_func_bytes()
        if code is None:
            return list()
        # get sleigh id
        sleigh_id = self._get_sleigh_id()
        if sleigh_id is None:
            return list()
        if DEBUG:
            print(f"[ {NAME} ] using sleigh id: {sleigh_id}")

        # translate to P-Code
        langs = {l.id: l for arch in Arch.enumerate() for l in arch.languages}
        if sleigh_id not in langs:
            return list()
        ctx = Context(langs[sleigh_id])
        res = ctx.translate(code=code, base=0, max_inst=0, bb_terminating=False)

        pcode_lines = list()
        f = ida_funcs.get_func(self._addr)
        for insn in res.instructions:
            # append asm text
            addr = insn.address.offset + f.start_ea
            asm_prefix = ida_lines.COLSTR(f"{addr:018X}", ida_lines.SCOLOR_PREFIX)
            asm_insn = ida_lines.COLSTR(
                f"{insn.asm_mnem.lower()} {insn.asm_body.lower()}",
                ida_lines.SCOLOR_INSN,
            )
            pcode_lines.append(f"{asm_prefix}  {asm_insn}")
            # append P-Code text
            for op in insn.ops:
                pcode_lines.append(f"  {PcodePrettyPrinter.fmt_op(op)}")

            pcode_lines.append("\n")

        return pcode_lines

    @property
    def func_name(self) -> str:
        if self._func_name is None:
            self._func_name = self._get_func_name()
        return self._func_name

    @property
    def pcode(self) -> List[str]:
        if self._func_pcode is None:
            self._func_pcode = self._get_pcode()
        return self._func_pcode


# -----------------------------------------------------------------------
class pcodecv_t(ida_kernwin.simplecustviewer_t):
    def Create(self, sn=None, use_colors=True):
        fpcode = FuncPcode(idaapi.get_screen_ea())

        title = f"P-Code for {fpcode.func_name}"
        if sn:
            title += f" {sn:#d}"
        self._use_colors = use_colors

        pcode_lines = fpcode.pcode
        if not pcode_lines:
            print(f"Can't get P-Code for function {fpcode.func_name}")
            return False

        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False

        for pcode_line in pcode_lines:
            self.AddLine(pcode_line)

        return True

    def OnClick(self, shift):
        if DEBUG:
            print(f"OnClick, shift={shift:#d}")
        return True

    def OnDblClick(self, shift):
        if DEBUG:
            print(f"OnDblClick, shift={shift:#d}")
        return True

    def OnCursorPosChanged(self):
        if DEBUG:
            print("OnCurposChanged")

    def OnClose(self):
        if DEBUG:
            print(f"{self.title} closed")

    def OnKeydown(self, vkey, shift):
        if DEBUG:
            print(f"OnKeydown, vk={vkey:#d} shift={shift:#d}")
        return True

    def OnHint(self, lineno):
        if DEBUG:
            return (1, f"OnHint, line={lineno:#d}")
        return (0, str())

    def Show(self, *args):
        return ida_kernwin.simplecustviewer_t.Show(self, *args)


# -----------------------------------------------------------------------
# Show P-Code View
def show_pcodecv():
    pcodecv = pcodecv_t()
    if not pcodecv.Create(use_colors=True):
        print(f"[ {NAME} ] failed to create view")
        return None
    pcodecv.Show()
    return pcodecv


# -----------------------------------------------------------------------
class IdaPcode(idaapi.plugin_t):
    """IDA P-Code plugin class"""

    flags = idaapi.PLUGIN_MOD | idaapi.PLUGIN_PROC | idaapi.PLUGIN_FIX
    comment = COMMENT_MSG
    help = HELP_MSG
    wanted_name = NAME
    wanted_hotkey = WANTED_KEY

    def init(self):
        print(f"\n{NAME} ({VERSION})")
        print(f"{NAME} shortcut key is {WANTED_KEY}\n")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        show_pcodecv()

    def term(self):
        if DEBUG:
            print(f"[ {NAME} ] terminated")


# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    try:
        return IdaPcode()
    except Exception as e:
        print(f"[ {NAME} ] {str(e)}\n{traceback.format_exc()}")


if __name__ == "__main__":
    try:
        show_pcodecv()
    except Exception as e:
        print(f"[ {NAME} ] {str(e)}\n{traceback.format_exc()}")
