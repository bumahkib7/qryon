//! Auto-generated python framework profiles
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::FrameworkProfile;

mod __aws_access_key_id_gen;
mod __aws_secret_access_key_gen;
mod __file_gen;
mod __name_gen;
mod _socket_gen;
mod airspeed_gen;
mod allowed_methods_gen;
mod argparse_gen;
mod args_gen;
mod asyncio_gen;
mod attachments_gen;
mod auth_gen;
mod aws_access_key_id_gen;
mod aws_key_gen;
mod aws_secret_access_key_gen;
mod aws_secret_gen;
mod baseexception_gen;
mod bcc_gen;
mod body_gen;
mod bufsize_gen;
mod cc_gen;
mod cert_file_gen;
mod chameleon_gen;
mod charset_gen;
mod cheetah_gen;
mod chevron_gen;
mod close_fds_gen;
mod cmd_gen;
mod code_gen;
mod command_gen;
mod content_gen;
mod content_type_gen;
mod cookies_gen;
mod cwd_gen;
mod data_gen;
mod defusedxml_gen;
mod dill_gen;
mod django_gen;
mod email_gen;
mod env_gen;
mod eval_gen;
mod exc_info_gen;
mod exec_gen;
mod executable_gen;
mod extra_gen;
mod fabric2_gen;
mod fabric_gen;
mod falcon_gen;
mod fastapi_gen;
mod file_gen;
mod filename_or_fp_gen;
mod flask_gen;
mod from_addr_gen;
mod from_email_gen;
mod genshi_gen;
mod header_gen;
mod headers_gen;
mod hooks_gen;
mod host_gen;
mod html_message_gen;
mod http_gen;
mod importlib_gen;
mod input_gen;
mod json_gen;
mod jsonpickle_gen;
mod key_file_gen;
mod key_gen;
mod linecache_gen;
mod link_gen;
mod lxml_gen;
mod mako_gen;
mod markdown_gen;
mod marshal_gen;
mod message_gen;
mod method_gen;
mod msg_gen;
mod mypy_boto3_acm_gen;
mod mypy_boto3_amplifybackend_gen;
mod mypy_boto3_apigateway_gen;
mod mypy_boto3_application_insights_gen;
mod mypy_boto3_apprunner_gen;
mod mypy_boto3_athena_gen;
mod mypy_boto3_braket_gen;
mod mypy_boto3_lambda_gen;
mod mypy_boto3_rds_data_gen;
mod mypy_boto3_redshift_data_gen;
mod mysql_gen;
mod mysqldb_gen;
mod name_gen;
mod origin_gen;
mod pandas_gen;
mod paramiko_gen;
mod params_gen;
mod pathlib_gen;
mod pexpect_gen;
mod pil_gen;
mod port_gen;
mod preexec_fn_gen;
mod protocols_gen;
mod proxies_gen;
mod proxy_auth_gen;
mod proxy_gen;
mod proxy_headers_gen;
mod psycopg2_gen;
mod pymssql_gen;
mod pymysql_gen;
mod pyre_gen;
mod python_http_gen;
mod python_stdlib_gen;
mod pyyaml_gen;
mod reason_gen;
mod recipient_list_gen;
mod reply_to_gen;
mod resource_gen;
mod rest_framework_gen;
mod runpy_gen;
mod secret_gen;
mod shelve_gen;
mod socketserver_gen;
mod sqlalchemy_gen;
mod sqlite3_gen;
mod stack_info_gen;
mod stdin_gen;
mod str_gen;
mod stream_gen;
mod subject_gen;
mod subsystem_gen;
mod text_gen;
mod timeout_gen;
mod to_addrs_gen;
mod to_gen;
mod token_gen;
mod tornado_gen;
mod trender_gen;
mod url_gen;
mod value_gen;
mod verify_gen;
mod wsgiref_gen;
mod xml_gen;

/// Get all generated python framework profiles.
pub fn generated_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &__aws_access_key_id_gen::__AWS_ACCESS_KEY_ID_GEN_PROFILE,
        &__aws_secret_access_key_gen::__AWS_SECRET_ACCESS_KEY_GEN_PROFILE,
        &__file_gen::__FILE_GEN_PROFILE,
        &__name_gen::__NAME_GEN_PROFILE,
        &_socket_gen::_SOCKET_GEN_PROFILE,
        &airspeed_gen::AIRSPEED_GEN_PROFILE,
        &allowed_methods_gen::ALLOWED_METHODS_GEN_PROFILE,
        &argparse_gen::ARGPARSE_GEN_PROFILE,
        &args_gen::ARGS_GEN_PROFILE,
        &asyncio_gen::ASYNCIO_GEN_PROFILE,
        &attachments_gen::ATTACHMENTS_GEN_PROFILE,
        &auth_gen::AUTH_GEN_PROFILE,
        &aws_access_key_id_gen::AWS_ACCESS_KEY_ID_GEN_PROFILE,
        &aws_key_gen::AWS_KEY_GEN_PROFILE,
        &aws_secret_gen::AWS_SECRET_GEN_PROFILE,
        &aws_secret_access_key_gen::AWS_SECRET_ACCESS_KEY_GEN_PROFILE,
        &baseexception_gen::BASEEXCEPTION_GEN_PROFILE,
        &bcc_gen::BCC_GEN_PROFILE,
        &body_gen::BODY_GEN_PROFILE,
        &bufsize_gen::BUFSIZE_GEN_PROFILE,
        &cc_gen::CC_GEN_PROFILE,
        &cert_file_gen::CERT_FILE_GEN_PROFILE,
        &chameleon_gen::CHAMELEON_GEN_PROFILE,
        &charset_gen::CHARSET_GEN_PROFILE,
        &cheetah_gen::CHEETAH_GEN_PROFILE,
        &chevron_gen::CHEVRON_GEN_PROFILE,
        &close_fds_gen::CLOSE_FDS_GEN_PROFILE,
        &cmd_gen::CMD_GEN_PROFILE,
        &code_gen::CODE_GEN_PROFILE,
        &command_gen::COMMAND_GEN_PROFILE,
        &content_gen::CONTENT_GEN_PROFILE,
        &content_type_gen::CONTENT_TYPE_GEN_PROFILE,
        &cookies_gen::COOKIES_GEN_PROFILE,
        &cwd_gen::CWD_GEN_PROFILE,
        &data_gen::DATA_GEN_PROFILE,
        &defusedxml_gen::DEFUSEDXML_GEN_PROFILE,
        &dill_gen::DILL_GEN_PROFILE,
        &django_gen::DJANGO_GEN_PROFILE,
        &email_gen::EMAIL_GEN_PROFILE,
        &env_gen::ENV_GEN_PROFILE,
        &eval_gen::EVAL_GEN_PROFILE,
        &exc_info_gen::EXC_INFO_GEN_PROFILE,
        &exec_gen::EXEC_GEN_PROFILE,
        &executable_gen::EXECUTABLE_GEN_PROFILE,
        &extra_gen::EXTRA_GEN_PROFILE,
        &fabric_gen::FABRIC_GEN_PROFILE,
        &fabric2_gen::FABRIC2_GEN_PROFILE,
        &falcon_gen::FALCON_GEN_PROFILE,
        &fastapi_gen::FASTAPI_GEN_PROFILE,
        &file_gen::FILE_GEN_PROFILE,
        &filename_or_fp_gen::FILENAME_OR_FP_GEN_PROFILE,
        &flask_gen::FLASK_GEN_PROFILE,
        &from_addr_gen::FROM_ADDR_GEN_PROFILE,
        &from_email_gen::FROM_EMAIL_GEN_PROFILE,
        &genshi_gen::GENSHI_GEN_PROFILE,
        &header_gen::HEADER_GEN_PROFILE,
        &headers_gen::HEADERS_GEN_PROFILE,
        &hooks_gen::HOOKS_GEN_PROFILE,
        &host_gen::HOST_GEN_PROFILE,
        &html_message_gen::HTML_MESSAGE_GEN_PROFILE,
        &http_gen::HTTP_GEN_PROFILE,
        &importlib_gen::IMPORTLIB_GEN_PROFILE,
        &input_gen::INPUT_GEN_PROFILE,
        &json_gen::JSON_GEN_PROFILE,
        &jsonpickle_gen::JSONPICKLE_GEN_PROFILE,
        &key_gen::KEY_GEN_PROFILE,
        &key_file_gen::KEY_FILE_GEN_PROFILE,
        &linecache_gen::LINECACHE_GEN_PROFILE,
        &link_gen::LINK_GEN_PROFILE,
        &lxml_gen::LXML_GEN_PROFILE,
        &mako_gen::MAKO_GEN_PROFILE,
        &markdown_gen::MARKDOWN_GEN_PROFILE,
        &marshal_gen::MARSHAL_GEN_PROFILE,
        &message_gen::MESSAGE_GEN_PROFILE,
        &method_gen::METHOD_GEN_PROFILE,
        &msg_gen::MSG_GEN_PROFILE,
        &mypy_boto3_acm_gen::MYPY_BOTO3_ACM_GEN_PROFILE,
        &mypy_boto3_amplifybackend_gen::MYPY_BOTO3_AMPLIFYBACKEND_GEN_PROFILE,
        &mypy_boto3_apigateway_gen::MYPY_BOTO3_APIGATEWAY_GEN_PROFILE,
        &mypy_boto3_application_insights_gen::MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_PROFILE,
        &mypy_boto3_apprunner_gen::MYPY_BOTO3_APPRUNNER_GEN_PROFILE,
        &mypy_boto3_athena_gen::MYPY_BOTO3_ATHENA_GEN_PROFILE,
        &mypy_boto3_braket_gen::MYPY_BOTO3_BRAKET_GEN_PROFILE,
        &mypy_boto3_lambda_gen::MYPY_BOTO3_LAMBDA_GEN_PROFILE,
        &mypy_boto3_rds_data_gen::MYPY_BOTO3_RDS_DATA_GEN_PROFILE,
        &mypy_boto3_redshift_data_gen::MYPY_BOTO3_REDSHIFT_DATA_GEN_PROFILE,
        &mysql_gen::MYSQL_GEN_PROFILE,
        &mysqldb_gen::MYSQLDB_GEN_PROFILE,
        &name_gen::NAME_GEN_PROFILE,
        &origin_gen::ORIGIN_GEN_PROFILE,
        &pandas_gen::PANDAS_GEN_PROFILE,
        &paramiko_gen::PARAMIKO_GEN_PROFILE,
        &params_gen::PARAMS_GEN_PROFILE,
        &pathlib_gen::PATHLIB_GEN_PROFILE,
        &pexpect_gen::PEXPECT_GEN_PROFILE,
        &pil_gen::PIL_GEN_PROFILE,
        &port_gen::PORT_GEN_PROFILE,
        &preexec_fn_gen::PREEXEC_FN_GEN_PROFILE,
        &protocols_gen::PROTOCOLS_GEN_PROFILE,
        &proxies_gen::PROXIES_GEN_PROFILE,
        &proxy_gen::PROXY_GEN_PROFILE,
        &proxy_auth_gen::PROXY_AUTH_GEN_PROFILE,
        &proxy_headers_gen::PROXY_HEADERS_GEN_PROFILE,
        &psycopg2_gen::PSYCOPG2_GEN_PROFILE,
        &pymssql_gen::PYMSSQL_GEN_PROFILE,
        &pymysql_gen::PYMYSQL_GEN_PROFILE,
        &pyre_gen::PYRE_GEN_PROFILE,
        &python_http_gen::PYTHON_HTTP_GEN_PROFILE,
        &python_stdlib_gen::PYTHON_STDLIB_GEN_PROFILE,
        &pyyaml_gen::PYYAML_GEN_PROFILE,
        &reason_gen::REASON_GEN_PROFILE,
        &recipient_list_gen::RECIPIENT_LIST_GEN_PROFILE,
        &reply_to_gen::REPLY_TO_GEN_PROFILE,
        &resource_gen::RESOURCE_GEN_PROFILE,
        &rest_framework_gen::REST_FRAMEWORK_GEN_PROFILE,
        &runpy_gen::RUNPY_GEN_PROFILE,
        &secret_gen::SECRET_GEN_PROFILE,
        &shelve_gen::SHELVE_GEN_PROFILE,
        &socketserver_gen::SOCKETSERVER_GEN_PROFILE,
        &sqlalchemy_gen::SQLALCHEMY_GEN_PROFILE,
        &sqlite3_gen::SQLITE3_GEN_PROFILE,
        &stack_info_gen::STACK_INFO_GEN_PROFILE,
        &stdin_gen::STDIN_GEN_PROFILE,
        &str_gen::STR_GEN_PROFILE,
        &stream_gen::STREAM_GEN_PROFILE,
        &subject_gen::SUBJECT_GEN_PROFILE,
        &subsystem_gen::SUBSYSTEM_GEN_PROFILE,
        &text_gen::TEXT_GEN_PROFILE,
        &timeout_gen::TIMEOUT_GEN_PROFILE,
        &to_gen::TO_GEN_PROFILE,
        &to_addrs_gen::TO_ADDRS_GEN_PROFILE,
        &token_gen::TOKEN_GEN_PROFILE,
        &tornado_gen::TORNADO_GEN_PROFILE,
        &trender_gen::TRENDER_GEN_PROFILE,
        &url_gen::URL_GEN_PROFILE,
        &value_gen::VALUE_GEN_PROFILE,
        &verify_gen::VERIFY_GEN_PROFILE,
        &wsgiref_gen::WSGIREF_GEN_PROFILE,
        &xml_gen::XML_GEN_PROFILE,
    ]
}
