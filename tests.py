import unittest
from battlestar_envoy_grapher import RoleGrapher


class TestRoleGrapher(unittest.TestCase):
    def setUp(self):
        self.grapher = RoleGrapher()
        self.grapher.service_entries["main-svc"] = set(["first-dep", "second-dep"])

    def test_simplify_service_name(self):
        self.assertEqual(self.grapher.simplify_service_name("battlestar-envoy-grapher"), "battlestar-envoy-grapher")
        self.assertEqual(self.grapher.simplify_service_name("battlestar-envoy-grapher-1"), "battlestar-envoy-grapher")
        self.assertEqual(self.grapher.simplify_service_name("battlestar-envoy-grapher-1-2"), "battlestar-envoy-grapher")

    def test_get_empty_dependency_graph(self):
        self.assertEqual(self.grapher.get_backends("svc-nodeps"), set())

    def test_get_dependency_graph_with_dependencies(self):
        self.assertEqual(self.grapher.get_backends("main-svc"), set(["first-dep", "second-dep"]))

    def test_build_graph(self):
        graph = self.grapher.build_graph("main-svc")
        # Assert that the node "main-svc" in graph has two dependencies, and that they are "first-dep" and "second-dep"
        self.assertEqual(graph.has_edge("main-svc", "first-dep"), True)
        self.assertEqual(graph.has_edge("main-svc", "second-dep"), True)


if __name__ == '__main__':
    unittest.main()
