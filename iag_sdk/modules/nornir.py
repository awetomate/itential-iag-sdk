from typing import Dict, Union

from iag_sdk.client_base import ClientBase


class Nornir(ClientBase):
    """
    Class that contains methods for the IAG Nornir API routes.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        headers: Dict,
        base_url: str = "/api/v2.0",
        protocol: str = "http",
        port: Union[int, str] = 8083,
        verify: bool = True,
    ) -> None:
        super().__init__(host, username, password, headers, base_url, protocol, port, verify)

    def delete_schema(self, name: str) -> Dict:
        """
        Remove a Nornir module schema.

        :param name: Name of the nornir module.
        """
        return self.query(f"/nornir/{name}/schema", method="delete")

    def execute(self, name: str, parameters: Dict) -> Dict:
        """
        Execute a Nornir module.
        Tip: Use get_nornir_module_schema() to get the format of the parameters object.

        :param name: Name of nornir module to execute.
        :param parameters: Module Execution Parameters.
        """
        return self.query(f"/nornir/{name}/execute", method="post", jsonbody=parameters)

    def get(self, name: str) -> Dict:
        """
        Get Nornir module information

        :param name: Name of nornir module to retrieve.
        """
        return self.query(f"/nornir/{name}")

    def get_history(
        self, name: str, offset: int = 0, limit: int = 10, order: str = "descending"
    ) -> Dict:
        """
        Get execution log events for a Nornir module.
        Tip: Use get_audit_log() and the audit_id returned by this call, to get the details of the execution.

        :param name: Name of the nornir module.
        :param offset: Optional. The number of items to skip before starting to collect the result set (default 0).
        :param limit: Optional. The number of items to return (default 10).
        :param order: Optional. Sort indication. Available values : ascending, descending (default).
        """
        return self.query(
            f"/nornir/{name}/history",
            params={"offset": offset, "limit": limit, "order": order},
        )

    def get_schema(self, name: str) -> Dict:
        """
        Get the schema for a Nornir module.

        :param name: Name of nornir module.
        """
        return self.query(f"/nornir/{name}/schema")

    def get_all(
        self,
        offset: int = 0,
        limit: int = 50,
        filter: str = None,
        order: str = "ascending",
        detail: str = "summary",
    ) -> Dict:
        """
        Get a list of Nornir modules.

        :param offset: The number of items to skip before starting to collect the result set.
        :param limit: The number of items to return (default 50).
        :param filter: Response filter function with JSON name/value pair argument as string, i.e., 'equals({"name":"sample"})' Valid filter functions - contains, equals, startswith, endswith
        :param order: Optional. Sort indication. Available values : ascending (default), descending.
        :param detail: Select detail level between 'full' (a lot of data) or 'summary' for each item.
        """
        return self.query(
            "/nornir",
            params={
                "offset": offset,
                "limit": limit,
                "filter": filter,
                "order": order,
                "detail": detail,
            },
        )

    def refresh(self) -> Dict:
        """
        Perform Nornir module discovery and update internal cache.
        """
        return self.query("/nornir/refresh", method="post")

    def update_schema(self, name: str, config_object: Dict) -> Dict:
        """
        Update/Insert a Nornir module schema document.
        Tip: Use get_nornir_module_schema() to get an idea of the format of the config_object.

        :param name: Name of nornir module.
        :param config_object: Schema to apply to nornir module identified in path.
        """
        return self.query(
            f"/nornir/{name}/schema", method="put", jsonbody=config_object
        )
