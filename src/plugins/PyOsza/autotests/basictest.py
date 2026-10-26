import Osza
import unittest

class BasicTest(unittest.TestCase):

    def test_module_version(self):
        self.assertEqual(Osza.__version__.count('.'), 2)
        self.assertIsNotNone(Osza.registerPlugin)

    def test_mainapplication(self):
        self.assertIsNotNone(Osza.MainApplication.instance())

    def test_create_window(self):
        window = Osza.MainApplication.instance().createWindow(Osza.Qz.BW_NewWindow)
        self.assertIsNotNone(window)

    def test_sql_availability(self):
        self.assertTrue(hasattr(Osza.SqlDatabase, 'database'))


suite = unittest.defaultTestLoader.loadTestsFromTestCase(BasicTest)
if unittest.TextTestRunner().run(suite).failures:
    raise(Exception("FAIL"))
