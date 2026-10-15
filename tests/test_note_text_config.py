from unittest import TestCase

from awsfindingsmanagerlib.note_text_config import NoteTextConfig


class TestNoteTextConfig(TestCase):
    def test_plaintext_mode_defaults_to_no_key(self):
        config = NoteTextConfig(Mode="plaintext")
        self.assertEqual(config.Key, "")

    def test_json_update_mode_requires_a_key(self):
        with self.assertRaises(ValueError):
            NoteTextConfig(Mode="jsonUpdate")

    def test_json_update_mode_with_a_key(self):
        config = NoteTextConfig(Mode="jsonUpdate", Key="suppressionReason")
        self.assertEqual(config.Key, "suppressionReason")

    def test_invalid_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            NoteTextConfig(Mode="invalid")

    def test_plaintext_mode_ignores_a_leftover_key_instead_of_raising(self):
        """Regression test.

        A rule commonly only overrides Mode back to 'plaintext' while the manager's
        DefaultRuleInput sets a Key for its own 'jsonUpdate' default. Manager._merge_inputs
        merges dict-wise, so Key survives into the merged ExtraFeatures.NoteTextConfig even
        though the rule never mentioned it. This used to raise ValueError, silently breaking
        the exact "Condensing big rule sets" pattern documented in docs/index.md.
        """
        config = NoteTextConfig(Mode="plaintext", Key="suppressionReason")
        self.assertEqual(config.Key, "")
