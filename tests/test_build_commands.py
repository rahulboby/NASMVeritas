import unittest

from server import Debugger, build_commands, has_global_symbol


class BuildCommandTests(unittest.TestCase):
    def test_i386_ld_build_uses_standalone_entry_point(self):
        commands, entry_point = build_commands("i386", "ld")
        self.assertEqual(commands, [
            ["nasm", "-f", "elf", "program.s", "-o", "program.o"],
            ["ld", "-m", "elf_i386", "program.o", "-o", "program"],
        ])
        self.assertEqual(entry_point, "_start")

    def test_i386_gcc_build_links_c_runtime(self):
        commands, entry_point = build_commands("i386", "gcc")
        self.assertEqual(commands[1], ["gcc", "-m32", "-no-pie", "program.o", "-o", "program"])
        self.assertEqual(entry_point, "main")

    def test_x86_64_builds_select_matching_linker_flags(self):
        ld_commands, ld_entry_point = build_commands("x86_64", "ld")
        gcc_commands, gcc_entry_point = build_commands("x86_64", "gcc")
        self.assertEqual(ld_commands, [
            ["nasm", "-f", "elf64", "program.s", "-o", "program.o"],
            ["ld", "-m", "elf_x86_64", "program.o", "-o", "program"],
        ])
        self.assertEqual(gcc_commands[1], ["gcc", "-m64", "-no-pie", "program.o", "-o", "program"])
        self.assertEqual(ld_entry_point, "_start")
        self.assertEqual(gcc_entry_point, "main")

    def test_rejects_unsupported_architecture_and_linker(self):
        with self.assertRaisesRegex(RuntimeError, "Unsupported architecture"):
            build_commands("arm64", "ld")
        with self.assertRaisesRegex(RuntimeError, "Unsupported linker"):
            build_commands("i386", "clang")

    def test_detects_required_global_entry_symbols(self):
        self.assertTrue(has_global_symbol("global main\nmain:", "main"))
        self.assertTrue(has_global_symbol("GLOBAL _start\n_start:", "_start"))
        self.assertTrue(has_global_symbol("global _start, main\nmain:", "main"))
        self.assertFalse(has_global_symbol("main:", "main"))

    def test_ld_rejects_main_and_explains_to_use_gcc(self):
        debugger = Debugger()
        with self.assertRaises(RuntimeError) as error:
            debugger.build("global main\nmain:", "i386", "ld")
        self.assertIsNone(debugger.gdb)
        self.assertIn("global _start", str(error.exception))
        self.assertIn("GCC", str(error.exception))


if __name__ == "__main__":
    unittest.main()
