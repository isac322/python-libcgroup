import unittest

from libcgroup import CGroup


class MyTestCase(unittest.TestCase):
    def test_something(self):
        cgroup = CGroup('test', 'cpuset')
        self.assertIsNotNone(cgroup)
        for key, val in cgroup.get_all_from('cpuset'):
            print(key, val)

        cgroup.add_current_thread()

        print('last get():', cgroup.get_from('cpuset', 'cgroup.procs'))

    def test_existing(self):
        cgroup = CGroup.from_existing('docker')
        self.assertIsNotNone(cgroup)
        for key, val in cgroup.get_all_from('cpuset'):
            print(key, val)

        print('from all controllers:')

        for key, val in cgroup.get_all():
            if val is not None:
                print(key, val, type(val))
            else:
                print(key, 'is None')


if __name__ == '__main__':
    unittest.main()
