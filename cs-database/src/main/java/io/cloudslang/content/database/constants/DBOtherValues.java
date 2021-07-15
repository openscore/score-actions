/*
 * (c) Copyright 2019 EntIT Software LLC, a Micro Focus company, L.P.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0 which accompany this distribution.
 *
 * The Apache License is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



package io.cloudslang.content.database.constants;

/**
 * Created by pinteae on 1/17/2017.
 */
public class DBOtherValues {
    public static final String ZERO = "0";
    public static final String DATABASE_NAME_CAP = "DatabaseName";
    public static final String SET_NOCOUNT_ON = "SET NOCOUNT ON";
    public static final String FORWARD_SLASH = "/";
    public static final String BACK_SLASH = "\\";
    public static final String SEMI_COLON = ";";
    public static final String DBMS_OUTPUT = "dbms_output";

    public static final String CONCUR_READ_ONLY = "CONCUR_READ_ONLY";
    public static final String CONCUR_UPDATABLE = "CONCUR_UPDATABLE";

    public static final String TYPE_FORWARD_ONLY = "TYPE_FORWARD_ONLY";
    public static final String TYPE_SCROLL_INSENSITIVE = "TYPE_SCROLL_INSENSITIVE";
    public static final String TYPE_SCROLL_SENSITIVE = "TYPE_SCROLL_SENSITIVE";

    public static final String ORACLE_DB_TYPE = "Oracle";
    public static final String MSSQL_DB_TYPE = "MSSQL";
    public static final String SYBASE_DB_TYPE = "Sybase";
    public static final String NETCOOL_DB_TYPE = "Netcool";
    public static final String DB2_DB_TYPE = "DB2";
    public static final String MYSQL_DB_TYPE = "MySQL";
    public static final String POSTGRES_DB_TYPE = "PostgreSQL";
    public static final String VERTICA_DB_TYPE = "Vertica";
    public static final String CUSTOM_DB_TYPE = "Custom";

    public static final Integer DEFAULT_PORT_ORACLE = 1521;
    public static final Integer DEFAULT_PORT_MSSQL = 1433;
    public static final Integer DEFAULT_PORT_SYBASE = 5000;
    public static final Integer DEFAULT_PORT_NETCOOL = 4100;
    public static final Integer DEFAULT_PORT_DB2 = 50000;
    public static final Integer DEFAULT_PORT_MYSQL = 3306;
    public static final Integer DEFAULT_PORT_PSQL = 5432;
    public static final Integer DEFAULT_PORT_VERTICA = 5433;
    public static final Integer DEFAULT_PORT_CUSTOM = DEFAULT_PORT_ORACLE;

    public static final String ORACLE_JDBC_DRIVER = "oracle.jdbc.driver.OracleDriver";
    public static final String SQLSERVER_JDBC_DRIVER = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
    public static final String SYBASE_JTDS_DRIVER = "net.sourceforge.jtds.jdbc.Driver";
    public static final String NETCOOL_DRIVER = "com.sybase.jdbc3.jdbc.SybDriver";
    public static final String DB2_DRIVER = "com.ibm.db2.jcc.DB2Driver";
    public static final String MYSQL_JDBC_DRIVER = "com.mysql.jdbc.Driver";
    public static final String POSTGRESQL_DRIVER = "org.postgresql.Driver";
    public static final String VERTICA_DRIVER = "com.vertica.jdbc.Driver";
    public static final String MSSQL_FILE_DRIVER = "sqljdbc_auth.dll";

    public static final String KEY_COLUMNS = "%s - Columns";
    public static final String KEY_FILES = "%s - Files";
    public static final String KEY_CLOB_NAMES = "%s - CLOBNames";
    public static final String KEY_SKIP = "%s - Skip";

    public static final String QUESTION_MARK = "?";
    public static final String AMPERSAND ="&";
    public static final String ZERO_DATE_TIME_BEHAVIOR = "zeroDateTimeBehavior=";
    public static final String ZERO_DATE_TIME_CONVERT_TO_NULL = "zeroDateTimeBehavior=convertToNull";

}
