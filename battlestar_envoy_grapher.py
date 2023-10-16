#!/usr/bin/env python3

"""
Create a directed acyclic graph for envoy backends, to make services to
dependencies.

Important things to know about this tool:
1. It uses the Battlestar API to get the list of roles and service
   entries.
2. It caches the results of the API calls for 1 hour.
    You can override this by passing --refresh.
3. It uses the keyring library to get your LDAP password.
4. By default it will run and cache the results. If you want an output image,
   pass --generate-image.
5. By default it will include all services. If you want to limit the services,
   pass --services.
6. You can limit nodes to display based on the number of connections they have.
   Use --min-connections and --max-connections.
7. We ignore any service that has "mysql" or "redis" in the name.
   This is to avoid cluttering the graph with database connections.
8. The Envoy backends describe egress from source to destination, whereas the
   firewall rules define ingress. We normalise this to always work on egress to
   show which services are dependent on which other services.
"""

import argparse
from collections import defaultdict
from queue import Queue
from threading import Thread
import keyring
import os
import pickle
import re
import requests
import time
import networkx as nx
import matplotlib.pyplot as plt

# Cache to store the contents of each file after it's read for the first time
cache = {}
dbre = re.compile('mysql|redis')
battlestar = "https://battlestar.corp.twilio.com/v2"


class RoleGrapher:
    username, password = None, None

    def __init__(self, debug=False):
        self.username, self.password = self.get_credentials()
        self.debug = debug
        self.roles = None
        self.service_entries = defaultdict(set)
        return

    def log(self, msg):
        """Log messages to stdout."""
        if self.debug:
            print(msg)
        return

    def get_credentials(self):
        """Get the credentials for the database."""
        # Get username from environment variable
        username = os.environ.get("USER")
        password = keyring.get_password("ldap_login", username)
        return username, password

    def cache(self, cache_type, data=None):
        """Check if the cache exists and is less than 1 hour old.

        If it is, return the contents of the cache. Otherwise, return None.

        If data is provided, write it to the cache."""

        if cache_type == "roles":
            cache_file_name = "roles.txt"
        elif cache_type == "service_entries":
            cache_file_name = "service_entries.txt"
        else:
            raise ValueError("Invalid cache type")

        # If we have data, write it to the cache
        if data:
            self.log(f"Writing {cache_file_name} to cache")
            with open(cache_file_name, 'wb') as fname:
                # We have to store the results as pickle objects, because set() isn't JSON serializable.
                pickle.dump(data, fname)
            return None

        # We didn't get data, so try to read from the cache
        if (os.path.exists(cache_file_name) and
                os.path.getsize(cache_file_name) > 0 and
                os.path.getmtime(cache_file_name) > time.time() - 3600):
            # Read the cache file, deserialize it, and return it
            self.log(f"Reading {cache_file_name} from cache")
            with open(cache_file_name, 'rb') as fname:
                data = pickle.load(fname)
            return data

        # We didn't get data, or the cache is too old, so return None
        return None

    def simplify_service_name(self, service):
        # If a service ends in "-<number>", strip off the dash and number to
        # collapse the space down.
        # This is to handle things like "service-1" and "service-2" having
        # different names, but they're really the same service.
        if re.search(r'-\d+$', service):
            service = service.rstrip('-0123456789')
        return service

    def get_roles_list(self, url=None, refresh=False):
        """Get the list of roles from the response.

        Save the results to a cache. If the cache is older than 1 hour,
        refresh it."""

        roles = []

        if not refresh:
            cached_data = self.cache("roles")
            if cached_data:
                self.roles = cached_data
                return

        if url is None:
            url = f"{battlestar}/Roles"
        response = requests.get(url=url,
                                auth=(self.username, self.password),
                                params={'page_size': 1000})
        roles_data = response.json()
        role_names = [x['name'] for x in roles_data['items']]
        roles.extend(role_names)

        if roles_data['meta']['next']:
            # The last instance of the recurrsion here returns None, and if we
            # don't catch it, we'll get a TypeError from `roles.extend(None)`.
            more_data = self.get_roles_list(url=roles_data['meta']['next'],
                                            refresh=True)
            if more_data:
                roles.extend(more_data)

        # Save to the cache
        self.cache("roles", roles)
        self.log(f"Returning {len(roles)} roles from API")
        self.roles = roles
        return

    def fetch_service_entries(self):
        """Pull service entries from Battlestar."""

        url = f"{battlestar}/ServiceEntries"

        while True:
            try:
                response = requests.get(url=url,
                                        auth=(self.username, self.password),
                                        params={'page_size': 1000})
                results = response.json()
            except Exception as e:
                self.log(f"Connection error fetching envoy backends: {e}")
                return
            for service in results['items']:
                role = service['service_name']
                role = self.simplify_service_name(role)
                try:
                    backends = [x['service_name'] for x in service['service_configuration']['backends']]
                    for backend in backends:
                        self.service_entries[role].add(backend)
                except KeyError:
                    pass

            if results['meta']['next']:
                url = results['meta']['next']
            else:
                break
        return

    def fetch_firewall_rules(self, q):
        """Pull firewall rules from Battlestar."""

        url = f"{battlestar}/Roles/%s/Rules"

        while True:
            # Get a role from the queue
            source_role = q.get()
            while True:
                # Pull the firewall rules for that role
                self.log(f"Processing rules for role {source_role}")
                try:
                    response = requests.get(url=(url % source_role),
                                            auth=(self.username, self.password),
                                            params={'page_size': 1000})
                    results = response.json()
                except Exception as e:
                    self.log(f"Connection error for role {source_role}: {e}")
                    # This operation isn't atomic, but it's the best we have.
                    # Claim the task as done, and then put it back on the queue
                    # so that it gets processed again.
                    q.task_done()
                    q.put(source_role)
                    return
                for rule in results['items']:
                    # Battlestar gives us the ingress rules for each role.
                    # We want to flip that around to get the implied egress.
                    destination_role = rule['ingress_role']
                    destination_role = self.simplify_service_name(destination_role)
                    self.service_entries[destination_role].add(source_role)

                if results['meta']['next']:
                    url = results['meta']['next']
                else:
                    break
            q.task_done()
        return

    def fetch_backends_from_battlestar(self, roles, refresh=False):
        """Get service backends from Battlestar.

        Save the results to a cache. If the cache is older than 1 hour, refresh it."""

        if not refresh:
            cached_data = self.cache("service_entries")
            if cached_data:
                self.service_entries = cached_data
                return

        self.log("Pulling service entries from Battlestar")
        self.fetch_service_entries()
        self.log("Pulling firewall rules from Battlestar")
        q = Queue()
        num_threads = 20
        for role in sorted(self.roles):
            q.put(role)
        for i in range(num_threads):
            worker = Thread(target=self.fetch_firewall_rules, args=(q,))
            worker.setDaemon(True)
            worker.start()
        q.join()

        # Save to the cache
        self.cache("service_entries", self.service_entries)
        self.log(f"Returning {len(self.service_entries)} service entries from API")
        return

    def get_backends(self, service):
        """Get the envoy backends for a service."""
        service = self.simplify_service_name(service)
        backends = self.service_entries[service]
        self.log(f"{service} has backends {backends}")
        return backends

    def build_graph(self, service, graph=None):
        """Recursively builds a graph based on service dependencies."""
        if graph is None:
            graph = nx.DiGraph()

        dependencies = self.get_backends(service)
        # self.log(f"Building graph for {service} with dependencies {dependencies}")
        for dependency in dependencies:
            if dependency == service:
                continue
            if graph.has_edge(service, dependency) or graph.has_edge(dependency, service):
                continue
            if dbre.search(service) or dbre.search(dependency):
                continue
            graph.add_edge(service, dependency)
            graph = self.build_graph(dependency, graph)
        return graph

    def clean_graph(self, graph, min_connections, max_connections):
        # Remove nodes with more than M connections
        nodes_to_remove = [node for node, degree in graph.degree() if degree > max_connections]
        for node in nodes_to_remove:
            graph.remove_node(node)

        # Remove nodes with fewer than N connections
        nodes_to_remove = [node for node, degree in graph.degree() if degree <= min_connections]
        for node in nodes_to_remove:
            graph.remove_node(node)

        return graph

    def generate_image(self, graph, output):
        """Generate an image of the graph."""

        self.log(f"Generating image of graph with {len(graph.nodes)} nodes and {len(graph.edges)} edges")

        pos = nx.nx_agraph.graphviz_layout(graph, prog="twopi")
        plt.figure(figsize=(36, 36))  # Optional: Set figure size, can adjust based on your needs
        nx.draw(graph, pos, with_labels=True, arrows=True, node_size=200,
                node_color="skyblue", font_size=12, width=2.0, edge_color="gray",
                alpha=0.6)
        plt.title("Directed Acyclic Graph (DAG) of Services")

        # Save as PNG
        plt.savefig(output, format="png")
        return


def main():
    """main"""

    # Command line argument parsing
    parser = argparse.ArgumentParser(description="Build a directed graph for services.")
    parser.add_argument("--debug", "-d",
                        action="store_true",
                        help="Enable debug mode.")
    parser.add_argument("--generate-image", "-g",
                        action="store_true",
                        help="Generate an image of the graph.")
    parser.add_argument("--max-connections", "-m",
                        type=int,
                        default=5,
                        help="Maximum connections a node can have to be included in the graph.")
    parser.add_argument("--min-connections", "-n",
                        type=int,
                        default=0,
                        help="Minimum connections a node must have to be included in the graph.")
    parser.add_argument("--output", "-o",
                        type=str,
                        default="output.png",
                        help="Output file")
    parser.add_argument("--refresh", "-r",
                        action="store_true",
                        help="Refresh the cache.")
    parser.add_argument("--services", "-s",
                        help="Comma separated list of services to build graphs for.", default="")

    args = parser.parse_args()

    graph = nx.DiGraph()
    grapher = RoleGrapher(debug=args.debug)

    # Collect the role and envoy backend data from Battlestar
    grapher.get_roles_list(url=None, refresh=args.refresh)
    grapher.fetch_backends_from_battlestar(grapher.roles, args.refresh)

    # Parse the services from the command line arguments
    if args.services:
        services = args.services.split(',')
    else:
        # If no service is provided via command line, use all available services
        services = grapher.roles

    for service in services:
        service = grapher.simplify_service_name(service)
        if not grapher.service_entries[service]:
            continue
        graph = grapher.build_graph(service, graph)

    # Clean up the nodes based on min/max requested
    graph = grapher.clean_graph(graph, args.min_connections, args.max_connections)

    # Print the graph if requested
    if args.generate_image:
        grapher.generate_image(graph, args.output)

    return


if __name__ == "__main__":
    main()
