from typing import Dict, List, Optional, Union

from iag_sdk.client_base import ClientBase


class Netmiko(ClientBase):
    """
    Class that contains methods for the IAG Netmiko API routes.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        base_url: Optional[str] = "/api/v2.0",
        protocol: Optional[str] = "http",
        port: Optional[Union[int, str]] = 8083,
        verify: Optional[bool] = True,
        session = None,
        token: Optional[str] = None
    ) -> None:
        super().__init__(host, username, password, base_url, protocol, port, verify, session, token)

    def execute_netmiko_send_command_legacy(
        self,
        host: str,
        commands: List[str],
        device_type: str,
        username: str = "",
        password: str = "",
        port: int = 22,
    ) -> Dict:
        """
        Wrapper of legacy netmiko send_command.
        Connection and command information https://ktbyers.github.io/netmiko/docs/netmiko/base_connection.html

        :param host: IP address of target device.
        :param commands: List of commands to send to the device (e.g. ["show version", "show ip int brief"]).
        :param device_type: Netmiko device type (e.g. cisco_ios).
        :param username: Optional. Username to authenticate with Netmiko device.
        :param password: Optional. Password to authenticate with Netmiko device.
        :param port: Optional. Network port (default 22).
        """
        parameters = {
            "commands": commands,
            "connection_options": {
                "device_type": device_type,
                "password": password,
                "port": port,
                "username": username,
            },
            "host": host,
        }
        return self._make_request(
            "/netmiko/send_command", method="post", jsonbody=parameters
        )

    def execute_netmiko_send_command_native(
        self,
        host: str,
        command_string: str,
        cmd_verify: bool = True,
        delay_factor: int = 1,
        expect_string: str = None,
        max_loops: int = 30,
        normalize: bool = True,
        strip_command: bool = True,
        strip_prompt: bool = True,
        textfsm_template: str = None,
        ttp_template: str = None,
        use_genie: bool = False,
        use_textfsm: bool = False,
        use_ttp: bool = False,
    ) -> Dict:
        """
        IAG Native Netmiko send_command.
        Netmiko's host/ip parameters are condensed to only host which allows hostname or ip.
        See base_connection for all other supported connection parameters: https://ktbyers.github.io/netmiko/docs/netmiko/base_connection.html
        See send_command for all supported command execution parameters: https://ktbyers.github.io/netmiko/docs/netmiko/index.html#netmiko.BaseConnection.send_command

        :param host: Netmiko device name or IP address.
        :param command_string: The command to be executed on the remote device (e.g. "show version").
        :param cmd_verify: Optional. Verify command echo before proceeding (default to True).
        :param delay_factor: Optional. Multiplying factor used to adjust delays (default to 1).
        :param expect_string: Optional. Regular expression pattern to use for determining end of output. If left blank will default to being based on router prompt.
        :param max_loops: Optional. Controls wait time in conjunction with delay_factor. Will default to be based upon the timeout in netmiko device.
        :param normalize: Optional. Ensure the proper enter is sent at end of command (default to True).
        :param strip_command: Optional. Remove the echo of the command from the output (default to True).
        :param strip_prompt: Optional. Remove the trailing router prompt from the output (default to True).
        :param textfsm_template: Optional. Name of template to parse output with; can be fully qualified path, relative path, or name of file in current directory. (default to None).
        :param ttp_template: Optional. Name of template to parse output with; can be fully qualified path, relative path, or name of file in current directory. (default to None).
        :param use_genie: Optional. Process command output through PyATS/Genie parser (default to False).
        :param use_textfsm: Optional. Process command output through TextFSM template (default to False).
        :param use_ttp: Optional. Process command output through TTP template (default to False).
        """
        parameters = {
            "cmd_verify": cmd_verify,
            "command_string": command_string,
            "delay_factor": delay_factor,
            "host": host,
            "max_loops": max_loops,
            "normalize": normalize,
            "strip_command": strip_command,
            "strip_prompt": strip_prompt,
            "use_genie": use_genie,
            "use_textfsm": use_textfsm,
            "use_ttp": use_ttp,
        }
        if expect_string:
            parameters["expect_string"] = expect_string
        if textfsm_template:
            parameters["textfsm_template"] = textfsm_template
        if ttp_template:
            parameters["ttp_template"] = ttp_template

        return self._make_request(
            "/netmiko/send_command/execute", method="post", jsonbody=parameters
        )

    def execute_send_config_set_legacy(
        self,
        host: str,
        config_commands: List[str],
        device_type: str,
        username: str = None,
        password: str = None,
        port: int = 22,
    ) -> Dict:
        """
        Wrapper of legacy netmiko send_config_set.
        Connection and command information https://ktbyers.github.io/netmiko/docs/netmiko/base_connection.html

        :param host: IP address of target device.
        :param config_commands: List of commands to send to the device (e.g. ["hostname ROUTER1", "interface Ethernet 1/1", " description ROUTER1 Uplink"]).
        :param device_type: Netmiko device type (e.g. cisco_ios).
        :param username: Optional. Username to authenticate with Netmiko device.
        :param password: Optional. Password to authenticate with Netmiko device.
        :param port: Optional. Network port (default 22).
        """
        parameters = {
            "config_commands": config_commands,
            "connection_options": {
                "device_type": device_type,
                "password": password,
                "port": port,
                "username": username,
            },
            "host": host,
        }
        return self._make_request(
            "/netmiko/send_config", method="post", jsonbody=parameters
        )

    def execute_send_config_set_native(
        self,
        host: str,
        config_commands: List[str],
        cmd_verify: bool = True,
        config_mode_command: str = None,
        delay_factor: int = 1,
        enter_config_mode: bool = True,
        error_pattern: str = None,
        exit_config_mode: bool = True,
        max_loops: int = 150,
        strip_command: bool = True,
        strip_prompt: bool = True,
    ) -> Dict:
        """
        IAG Native Netmiko send_config_set.
        Netmiko's host/ip parameters are condensed to only host which allows hostname or ip.
        See base_connection for all other supported connection parameters: https://ktbyers.github.io/netmiko/docs/netmiko/base_connection.html
        See send_command for all supported command execution parameters: https://ktbyers.github.io/netmiko/docs/netmiko/index.html#netmiko.BaseConnection.send_command

        :param host: Netmiko device name or IP address
        :param config_commands: Multiple configuration commands to be sent to the device (e.g. ["hostname ROUTER1", "interface Ethernet 1/1", " description ROUTER1 Uplink"]).
        :param cmd_verify: Optional. Whether or not to verify command echo for each command in config_set.
        :param config_mode_command: Optional. The command to enter into config mode.
        :param delay_factor: Optional. Multiplying factor used to adjust delays (default to 1).
        :param enter_config_mode: Optional. Do you enter config mode before sending config commands
        :param error_pattern: Optional. Regular expression pattern to detect config errors in the output.
        :param exit_config_mode: Optional. Determines whether or not to exit config mode after complete.
        :param max_loops: Optional. Controls wait time in conjunction with delay_factor. Will default to be based upon the timeout in netmiko device (default 150).
        :param strip_command: Optional. Remove the echo of the command from the output (default to True).
        :param strip_prompt: Optional. Remove the trailing router prompt from the output (default to True).
        """
        parameters = {
            "cmd_verify": cmd_verify,
            "config_commands": config_commands,
            "delay_factor": delay_factor,
            "enter_config_mode": enter_config_mode,
            "exit_config_mode": exit_config_mode,
            "host": host,
            "max_loops": max_loops,
            "strip_command": strip_command,
            "strip_prompt": strip_prompt,
        }
        if config_mode_command:
            parameters["config_mode_command"] = config_mode_command
        if error_pattern:
            parameters["error_pattern"] = error_pattern

        return self._make_request(
            "/netmiko/send_config_set/execute", method="post", jsonbody=parameters
        )

    def get_send_command_history(
        self,
        send_command_type: str = "native",
        offset: int = 0,
        limit: int = 10,
        order: str = "descending",
    ) -> Dict:
        """
        Get execution log events for the Netmiko send_command.
        Tip: Use get_audit_log() and the audit_id returned by this call, to get the details of the execution.

        :param send_command_type: Optional. Choose between the IAG "native" (default) and the "legacy" netmiko send_command wrapper.
        :param offset: Optional.The number of items to skip before starting to collect the result set.
        :param limit: Optional.The number of items to return (default 10).
        :param order: Optional. Sort indication. Available values : 'ascending', 'descending' (default).
        """
        if send_command_type == "native":
            return self._make_request(
                f"/netmiko/send_command/history",
                params={"offset": offset, "limit": limit, "order": order},
            )
        else:
            return self._make_request(
                f"/netmiko/send_command/legacy_history",
                params={"offset": offset, "limit": limit, "order": order},
            )

    def get_send_config_set_history(
        self,
        send_config_set_type: str = "native",
        offset: int = 0,
        limit: int = 10,
        order: str = "descending",
    ) -> Dict:
        """
        Get execution log events for the Netmiko send_command.
        Tip: Use get_audit_log() and the audit_id returned by this call, to get the details of the execution.

        :param send_config_set_type: Optional. Choose between the IAG "native" (default) and the "legacy" netmiko send_config_set wrapper.
        :param offset: Optional.The number of items to skip before starting to collect the result set.
        :param limit: Optional.The number of items to return (default 10).
        :param order: Optional. Sort indication. Available values : 'ascending', 'descending' (default).
        """
        if send_config_set_type == "native":
            return self._make_request(
                f"/netmiko/send_config_set/history",
                params={"offset": offset, "limit": limit, "order": order},
            )
        else:
            return self._make_request(
                f"/netmiko/send_config/legacy_history",
                params={"offset": offset, "limit": limit, "order": order},
            )

    def get_command_schema(self, netmiko_command: str) -> Dict:
        """
        Get IAG Native Netmiko command schema.

        :param netmiko_command: Name of netmiko command. Available values : send_command, send_config_set
        """
        return self._make_request(f"/netmiko/{netmiko_command}/schema")
