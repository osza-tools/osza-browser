import Veex
import unittest

class BasicTest(unittest.TestCase):

    def test_module_version(self):
        self.assertEqual(Veex.__version__.count('.'), 2)
        self.assertIsNotNone(Veex.registerPlugin)

    def test_mainapplication(self):
        self.assertIsNotNone(Veex.MainApplication.instance())

    def test_create_window(self):
        window = Veex.MainApplication.instance().createWindow(Veex.Qz.BW_NewWindow)
        self.assertIsNotNone(window)

    def test_sql_availability(self):
        self.assertTrue(hasattr(Veex.SqlDatabase, 'database'))


suite = unittest.defaultTestLoader.loadTestsFromTestCase(BasicTest)
if unittest.TextTestRunner().run(suite).failures:
    raise(Exception("FAIL"))
