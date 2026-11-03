import unittest

from server import exited_state, parse_mi_integer, stopped_info


class ParseMiIntegerTests(unittest.TestCase):
    def test_signed_decimal_values(self):
        self.assertEqual(parse_mi_integer("-2"), -2)
        self.assertEqual(parse_mi_integer("+42"), 42)

    def test_zero_padded_decimal_values(self):
        self.assertEqual(parse_mi_integer("00000008"), 8)

    def test_hexadecimal_values_with_symbol_annotations(self):
        self.assertEqual(parse_mi_integer("0xfffffffe"), 0xFFFFFFFE)
        self.assertEqual(parse_mi_integer("0x401000 <_start>"), 0x401000)

    def test_rejects_non_numeric_values(self):
        with self.assertRaises(ValueError):
            parse_mi_integer("[ IF ]")


class GdbStopInfoTests(unittest.TestCase):
    def test_signal_stop_is_kept_distinct_from_process_exit(self):
        stop = stopped_info([
            '*stopped,reason="signal-received",signal-name="SIGSEGV",'
            'signal-meaning="Segmentation fault",frame={addr="0x8049000"}'
        ])
        self.assertEqual(stop["reason"], "signal-received")
        self.assertEqual(stop["signal_name"], "SIGSEGV")
        self.assertEqual(stop["signal_meaning"], "Segmentation fault")

    def test_signal_termination_does_not_attempt_to_read_registers(self):
        stop = stopped_info([
            '*stopped,reason="exited-signalled",signal-name="SIGSEGV",'
            'signal-meaning="Segmentation fault"'
        ])
        state = exited_state("i386", stop)
        self.assertEqual(state["status"], "signal_exit")
        self.assertEqual(state["registers"], {})
        self.assertEqual(state["signal_name"], "SIGSEGV")


if __name__ == "__main__":
    unittest.main()
