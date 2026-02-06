//! Auto-generated go framework profiles
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::FrameworkProfile;

mod cloud_gen;
mod database_sql_driver_gen;
mod database_sql_gen;
mod encoding_gob_gen;
mod encoding_json_gen;
mod encoding_pem_gen;
mod encoding_xml_gen;
mod fmt_gen;
mod github_gen;
mod go_gen;
mod go_html_gen;
mod golang_gen;
mod gopkg_gen;
mod group_beego_context_gen;
mod group_beego_gen;
mod group_beego_logs_gen;
mod group_beego_orm_gen;
mod group_beego_utils_gen;
mod group_clever_go_gen;
mod group_glog_gen;
mod group_go_jose_gen;
mod group_go_jose_jwt_gen;
mod group_gocb1_gen;
mod group_gocb2_gen;
mod group_gokogiri_xml_gen;
mod group_gokogiri_xpath_gen;
mod group_gorm_gen;
mod group_gorqlite_gen;
mod group_iris_context_gen;
mod group_logrus_gen;
mod group_revel_gen;
mod group_squirrel_gen;
mod group_xmlpath_gen;
mod group_xorm_gen;
mod html_template_gen;
mod io_fs_gen;
mod io_ioutil_gen;
mod k8s_gen;
mod log_gen;
mod mime_gen;
mod mime_quotedprintable_gen;
mod net_http_gen;
mod net_url_gen;
mod nhooyr_gen;
mod node_core_gen;
mod os_exec_gen;
mod path_filepath_gen;
mod python_stdlib_gen;
mod reflect_gen;
mod regexp_gen;
mod strconv_gen;
mod syscall_gen;
mod text_template_gen;

/// Get all generated go framework profiles.
pub fn generated_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &cloud_gen::CLOUD_GEN_PROFILE,
        &database_sql_gen::DATABASE_SQL_GEN_PROFILE,
        &database_sql_driver_gen::DATABASE_SQL_DRIVER_GEN_PROFILE,
        &encoding_gob_gen::ENCODING_GOB_GEN_PROFILE,
        &encoding_json_gen::ENCODING_JSON_GEN_PROFILE,
        &encoding_pem_gen::ENCODING_PEM_GEN_PROFILE,
        &encoding_xml_gen::ENCODING_XML_GEN_PROFILE,
        &fmt_gen::FMT_GEN_PROFILE,
        &github_gen::GITHUB_GEN_PROFILE,
        &go_gen::GO_GEN_PROFILE,
        &go_html_gen::GO_HTML_GEN_PROFILE,
        &golang_gen::GOLANG_GEN_PROFILE,
        &gopkg_gen::GOPKG_GEN_PROFILE,
        &group_beego_gen::GROUP_BEEGO_GEN_PROFILE,
        &group_beego_context_gen::GROUP_BEEGO_CONTEXT_GEN_PROFILE,
        &group_beego_logs_gen::GROUP_BEEGO_LOGS_GEN_PROFILE,
        &group_beego_orm_gen::GROUP_BEEGO_ORM_GEN_PROFILE,
        &group_beego_utils_gen::GROUP_BEEGO_UTILS_GEN_PROFILE,
        &group_clever_go_gen::GROUP_CLEVER_GO_GEN_PROFILE,
        &group_glog_gen::GROUP_GLOG_GEN_PROFILE,
        &group_go_jose_gen::GROUP_GO_JOSE_GEN_PROFILE,
        &group_go_jose_jwt_gen::GROUP_GO_JOSE_JWT_GEN_PROFILE,
        &group_gocb1_gen::GROUP_GOCB1_GEN_PROFILE,
        &group_gocb2_gen::GROUP_GOCB2_GEN_PROFILE,
        &group_gokogiri_xml_gen::GROUP_GOKOGIRI_XML_GEN_PROFILE,
        &group_gokogiri_xpath_gen::GROUP_GOKOGIRI_XPATH_GEN_PROFILE,
        &group_gorm_gen::GROUP_GORM_GEN_PROFILE,
        &group_gorqlite_gen::GROUP_GORQLITE_GEN_PROFILE,
        &group_iris_context_gen::GROUP_IRIS_CONTEXT_GEN_PROFILE,
        &group_logrus_gen::GROUP_LOGRUS_GEN_PROFILE,
        &group_revel_gen::GROUP_REVEL_GEN_PROFILE,
        &group_squirrel_gen::GROUP_SQUIRREL_GEN_PROFILE,
        &group_xmlpath_gen::GROUP_XMLPATH_GEN_PROFILE,
        &group_xorm_gen::GROUP_XORM_GEN_PROFILE,
        &html_template_gen::HTML_TEMPLATE_GEN_PROFILE,
        &io_fs_gen::IO_FS_GEN_PROFILE,
        &io_ioutil_gen::IO_IOUTIL_GEN_PROFILE,
        &k8s_gen::K8S_GEN_PROFILE,
        &log_gen::LOG_GEN_PROFILE,
        &mime_gen::MIME_GEN_PROFILE,
        &mime_quotedprintable_gen::MIME_QUOTEDPRINTABLE_GEN_PROFILE,
        &net_http_gen::NET_HTTP_GEN_PROFILE,
        &net_url_gen::NET_URL_GEN_PROFILE,
        &nhooyr_gen::NHOOYR_GEN_PROFILE,
        &node_core_gen::NODE_CORE_GEN_PROFILE,
        &os_exec_gen::OS_EXEC_GEN_PROFILE,
        &path_filepath_gen::PATH_FILEPATH_GEN_PROFILE,
        &python_stdlib_gen::PYTHON_STDLIB_GEN_PROFILE,
        &reflect_gen::REFLECT_GEN_PROFILE,
        &regexp_gen::REGEXP_GEN_PROFILE,
        &strconv_gen::STRCONV_GEN_PROFILE,
        &syscall_gen::SYSCALL_GEN_PROFILE,
        &text_template_gen::TEXT_TEMPLATE_GEN_PROFILE,
    ]
}
