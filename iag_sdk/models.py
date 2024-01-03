from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, RootModel, Field, StringConstraints, model_validator
from typing_extensions import Annotated


class Detail(Enum):
    full = "full"
    summary = "summary"


class Order(Enum):
    ascending = "ascending"
    descending = "descending"

class UpdateMerged(Enum):
    patch = "patch"
    put = "put"


class AccountModel(BaseModel):
    email: Optional[str] = None
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    username: str


class AccountParameters(BaseModel):
    email: str
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    password: str
    username: str


class AccountUpdateParameters(BaseModel):
    email: str
    firstname: str
    lastname: str


class AccountUpdatePassword(BaseModel):
    new_password: str
    old_password: str

    @model_validator(mode="after")
    def check_passwords_do_not_match(self) -> "AccountUpdatePassword":
        pw1 = self.new_password
        pw2 = self.old_password
        if pw1 is not None and pw2 is not None and pw1 == pw2:
            raise ValueError("New password cannot be same as old password!")
        return self


class ConfigParameters(BaseModel):
    class Config:
        extra = "forbid"

    ansible_debug: Optional[bool] = None
    ansible_enabled: Optional[bool] = None
    collection_path: Optional[List[str]] = Field(None, min_items=0)
    extended_device_role_path: Optional[List[str]] = Field(None, min_items=0)
    http_requests_enabled: Optional[bool] = None
    inventory_file: Optional[str] = None
    ldap_always_search_bind: Optional[bool] = None
    ldap_auth_enabled: Optional[bool] = None
    ldap_base_dn: Optional[str] = None
    ldap_bind_user_dn: Optional[str] = None
    ldap_bind_user_password: Optional[str] = None
    ldap_ca_certs_file: Optional[str] = None
    ldap_group_dn: Optional[str] = None
    ldap_group_members_attr: Optional[str] = None
    ldap_group_search_filter: Optional[str] = None
    ldap_group_search_scope: Optional[str] = None
    ldap_secure_enabled: Optional[bool] = None
    ldap_secure_validation_enabled: Optional[bool] = None
    ldap_secure_validation_tls_version: Optional[str] = None
    ldap_server: Optional[str] = None
    ldap_user_dn: Optional[str] = None
    ldap_user_login_attr: Optional[str] = None
    ldap_user_rdn_attr: Optional[str] = None
    ldap_user_search_filter: Optional[str] = None
    ldap_user_search_scope: Optional[str] = None
    module_path: Optional[List[str]] = Field(None, min_items=0)
    netconf_enabled: Optional[bool] = None
    netmiko_enabled: Optional[bool] = None
    no_cleanup: Optional[bool] = None
    nornir_config_file: Optional[str] = None
    nornir_enabled: Optional[bool] = None
    nornir_module_path: Optional[List[str]] = Field(None, min_items=0)
    nornir_module_recursive: Optional[bool] = None
    playbook_path: Optional[List[str]] = Field(None, min_items=0)
    playbook_recursive: Optional[bool] = None
    process_count: Optional[Annotated[int, Field(strict=True, ge=0)]] = None
    repos_enabled: Optional[bool] = None
    repos_path: Optional[str] = None
    role_path: Optional[List[str]] = Field(None, min_items=0)
    script_path: Optional[List[str]] = Field(None, min_items=0)
    script_recursive: Optional[bool] = None
    scripts_enabled: Optional[bool] = None
    terraform_enabled: Optional[bool] = None
    terraform_path: Optional[List[str]] = Field(None, min_items=0)
    terraform_recursive: Optional[bool] = None
    vault_access_token: Optional[str] = None
    vault_ca_file: Optional[str] = None
    vault_cert_verification: Optional[bool] = None
    vault_client_cert_file: Optional[str] = None
    vault_client_key_file: Optional[str] = None
    vault_enabled: Optional[bool] = None
    vault_mount_point: Optional[str] = None
    vault_password_file: Optional[str] = None
    vault_server: Optional[str] = None


class DeviceAddParameters(BaseModel):
    name: Annotated[str, StringConstraints(min_length=1)]
    variables: Dict[str, Any]


class DeviceUpdateParameters(BaseModel):
    variables: Dict[str, Any]


class GroupAddParameters(BaseModel):
    childGroups: Optional[List[str]] = None
    devices: List[str]
    name: Annotated[str, StringConstraints(min_length=1)]
    variables: Optional[Dict[str, Any]] = None


class GroupUpdateParameters(BaseModel):
    variables: Dict[str, Any]


class GroupChildren(RootModel):
    root: List[str]


class GroupDevices(RootModel):
    root: List[str]


class Auth(BaseModel):
    class Config:
        extra = "forbid"

    password: str = Field(..., example="password")
    username: str = Field(..., example="username")


class Method(Enum):
    get = "get"
    GET = "GET"
    options = "options"
    OPTIONS = "OPTIONS"
    head = "head"
    HEAD = "HEAD"
    post = "post"
    POST = "POST"
    put = "put"
    PUT = "PUT"
    patch = "patch"
    PATCH = "PATCH"
    delete = "delete"
    DELETE = "DELETE"


class Timeout(BaseModel):
    class Config:
        extra = "forbid"

    connect: Optional[str] = Field(None, example="3.05")
    read: Optional[str] = Field(None, example="27")


class HttpRequestsExecuteParameters(BaseModel):
    class Config:
        extra = "forbid"
        use_enum_values = True

    allow_redirects: Optional[bool] = Field(True, description="A flag which enables or disables HTTP redirection.", example="true",)
    auth: Optional[Auth] = Field(None, description="Keys/values to send as the username and password for Basic Authentication.", example={"password": "password", "username": "username"},)
    cookies: Optional[Dict[str, Any]] = Field(None, description="Keys/values to send as the request's cookies.", example={})
    data: Optional[Dict[str, Any]] = Field(None, description="Keys/values to send as the request's body.", example={})
    endpoint: str = Field(..., description="The endpoint to append to the url built from your inventory/host.", example="/api/v2/todos",)
    headers: Optional[Dict[str, Any]] = Field(None, description="Keys/values to send as the request's HTTP headers.", example={"content-type": "application/json"},)
    host: str = Field(..., description="The name of a host to execute against.", example="IOS")
    method: Method = Field(..., description="Request method - one of GET, OPTIONS, HEAD, POST, PUT, PATCH, DELETE", example="GET",)
    params: Optional[Dict[str, Any]] = Field(None, description="Keys/values to convert into the request's query string.", example={"id": "1"},)
    proxies: Optional[Dict[str, Any]] = Field(None, description="The keys/values which describe proxies to use for the request.", example={"http": "http://10.0.0.1:8080", "https": "http://10.0.0.1:4343"},)
    timeout: Optional[Timeout] = Field(None, description="The connect and read timeouts for the request. See: https://docs.python-requests.org/en/latest/user/advanced/#timeouts", example={"connect": "3.05", "read": "27"},)
    verify: Optional[bool] = Field(True, description="A flag which enables or disables TLS certificate verification.", example="false",)


class PathParam(BaseModel):
    name: Annotated[str, StringConstraints(min_length=1)]


class PathParams(PathParam):
    module: Annotated[str, StringConstraints(min_length=1)]


class QueryParams(BaseModel):
    class Config:
        use_enum_values = True

    offset: Optional[int] = Field(None, description="The number of items to skip before starting to collect the result set.",)
    limit: Optional[int] = Field(None, description="The number of items to return.")
    order: Optional[Order] = Field("descending", description="Sort indication. Available values : ascending, descending",)


class QueryParamsFilter(QueryParams):
    filter: Optional[str] = Field(None, description='Response filter function with JSON name/value pair argument, i.e., contains({"username":"admin"}) Valid filter functions - contains, equals, startswith, endswith',)


class QueryParamsDetail(QueryParamsFilter):
    detail: Optional[Detail] = "summary"


class ServerParams(BaseModel):
    auth_url: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    url: Optional[str] = None
    username: Optional[str] = None


class UpdateMethod(BaseModel):
    class Config:
        use_enum_values = True
    
    method: UpdateMerged


class CollectionInstallParameters(BaseModel):
    filename: Optional[str] = Field(None, description="Path to package if installing locally")
    force: Optional[bool] = Field(None, description="Add force flag to force package installation (when collection is already installed and you want to upgrade or downgrade version)",)
    package_name: Optional[str] = Field(None, description="Name of package to install if installing from Galaxy server")
    server_params: Optional[ServerParams] = Field(None, description="Parameters for connection to Galaxy server")
    version: Optional[str] = Field(None, description="Version of Collection to be installed")


class ModuleExecuteParameters(BaseModel):
    args: Dict[str, Any]
    groups: Optional[List[str]] = None
    hosts: Optional[List[str]] = None
    provider_required: Optional[bool] = Field(None, description="Enable/disable automation of provider object")
    strict_args: Optional[bool] = Field(None, description="Override global strict args setting")
    template: Optional[str] = Field(None, description="TextFSM template")


class RoleExecuteParameters(BaseModel):
    args: Dict[str, Any]
    groups: Optional[List[str]] = None
    hosts: Optional[List[str]] = None
    strict_args: Optional[bool] = Field(None, description="Override global strict args setting")
    template: Optional[str] = Field(None, description="TextFSM template")


class Schema(BaseModel):
    properties: Optional[Dict[str, Any]] = None
    required: Optional[List[str]] = None
    title: Optional[str] = None
    type: Optional[str] = None
