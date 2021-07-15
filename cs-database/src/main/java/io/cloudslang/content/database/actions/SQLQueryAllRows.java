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



package io.cloudslang.content.database.actions;


import com.hp.oo.sdk.content.annotations.Action;
import com.hp.oo.sdk.content.annotations.Output;
import com.hp.oo.sdk.content.annotations.Param;
import com.hp.oo.sdk.content.annotations.Response;
import com.hp.oo.sdk.content.plugin.ActionMetadata.MatchType;
import com.hp.oo.sdk.content.plugin.ActionMetadata.ResponseType;
import io.cloudslang.content.constants.ResponseNames;
import io.cloudslang.content.database.services.SQLQueryAllRowsService;
import io.cloudslang.content.database.utils.SQLInputs;
import io.cloudslang.content.utils.OutputUtilities;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Map;

import static io.cloudslang.content.constants.BooleanValues.FALSE;
import static io.cloudslang.content.constants.OtherValues.COMMA_DELIMITER;
import static io.cloudslang.content.constants.OutputNames.*;
import static io.cloudslang.content.constants.ReturnCodes.FAILURE;
import static io.cloudslang.content.constants.ReturnCodes.SUCCESS;
import static io.cloudslang.content.database.constants.DBDefaultValues.*;
import static io.cloudslang.content.database.constants.DBInputNames.*;
import static io.cloudslang.content.database.constants.DBOtherValues.*;
import static io.cloudslang.content.database.utils.SQLInputsUtils.*;
import static io.cloudslang.content.database.utils.SQLInputsValidator.validateSqlQueryAllRowsInputs;
import static io.cloudslang.content.utils.BooleanUtilities.toBoolean;
import static io.cloudslang.content.utils.NumberUtilities.toInteger;
import static io.cloudslang.content.utils.OutputUtilities.getFailureResultsMap;
import static org.apache.commons.lang3.StringUtils.EMPTY;
import static org.apache.commons.lang3.StringUtils.defaultIfEmpty;

/**
 * Created by pinteae on 1/10/2017.
 */
public class SQLQueryAllRows {

    /**
     * @param dbServerName              The hostname or ip address of the database server.
     * @param dbType                    The type of database to connect to
     *                                  Valid values: Oracle, MSSQL, Sybase, Netcool, DB2, PostgreSQL, Vertica and Custom.
     *                                  Default value: Oracle
     * @param username                  The username to use when connecting to the server.
     * @param password                  The password to use when connecting to the server.
     * @param instance                  The name instance of MSSQL Server. Leave it blank for default instance.
     *                                  Example: MSSQLSERVER
     * @param dbPort                    The port to connect to.
     *                                  Default values: Oracle: 1521, MSSQL: 1433, Sybase: 5000, Netcool: 4100, DB2: 50000, PostgreSQL: 5432, Vertica:5433.
     * @param databaseName              The name of the database to connect to.
     * @param authenticationType        The type of authentication used to access the database (applicable only to MSSQL type).
     *                                  Default: sql
     *                                  Values: sql, windows
     * @param dbClass                   The classname of the JDBC driver to use.
     *                                  Examples: "oracle.jdbc.driver.OracleDriver", "org.postgresql.Driver"
     * @param dbURL                     The url required to load up the driver and make your connection.
     *                                  Examples: "jdbc:oracle:drivertype:@database", "jdbc:postgresql://host:port/database"
     * @param command                   The SQL query to execute.
     *                                  Example: "SELECT * FROM table"
     * @param trustAllRoots             Specifies whether to enable weak security over SSL/TSL. A certificate is trusted even if no trusted certification authority issued it.
     *                                  Default value: false
     *                                  Valid values: true, false
     *                                  Note: If trustAllRoots is set to 'false', a trustStore and a trustStorePassword must be provided.
     * @param trustStore                The pathname of the Java TrustStore file. This contains certificates from other parties that you expect to communicate with,
     *                                  or from Certificate Authorities that you trust to identify other parties.
     *                                  If the trustAllRoots input is set to 'true' this input is ignored.
     * @param trustStorePassword        The password associated with the trustStore file.
     * @param authLibraryPath           The path to the folder where sqljdbc_auth.dll is located. This path must be provided when using windows authentication.
     *                                  Note: The sqljdbc_auth.dll can be found inside the sqljdbc driver. The driver can be downloaded from https://www.microsoft.com/en-us/download/details.aspx?id=11774.
     *                                  The downloaded jar should be extracted and the library can be found in the 'auth' folder.
     *                                  The path provided should be the path to the folder where the sqljdbc_auth.dll library is located, not the path to the file itself.
     * @param colDelimiter              The delimiter to use between columns in resulting table.
     *                                  Default value: comma (,)
     * @param rowDelimiter              The delimiter to use between rows in resulting table.
     *                                  Default value: \n
     * @param timeout                   Seconds to wait before timing out the SQL command execution. When the default value is used, there
     *                                  is no limit on the amount of time allowed for a running command to complete.
     *                                  Default values: 0
     * @param databasePoolingProperties Properties for database pooling configuration. Pooling is disabled by default.
     *                                  Default: db.pooling.enable=false
     *                                  Example: db.pooling.enable=true
     * @param resultSetType             the result set type. See JDBC folder description for more details.
     *                                  Valid values: TYPE_FORWARD_ONLY, TYPE_SCROLL_INSENSITIVE,TYPE_SCROLL_SENSITIVE.
     *                                  Default value: TYPE_SCROLL_INSENSITIVE except for DB2 and Vertica which is overridden to TYPE_FORWARD_ONLY
     * @param resultSetConcurrency      the result set concurrency. See JDBC folder description for more details.
     *                                  Valid values: CONCUR_READ_ONLY, CONCUR_UPDATABLE
     *                                  Default value: CONCUR_READ_ONLY
     * @return Return the list of all the data returned by the query. It is delimited by colDelimiter and rowDelimiter.
     */
    @Action(name = "SQL Query All Rows",
            outputs = {
                    @Output(RETURN_CODE),
                    @Output(RETURN_RESULT),
                    @Output(EXCEPTION)
            },
            responses = {
                    @Response(text = ResponseNames.SUCCESS, field = RETURN_CODE, value = SUCCESS,
                            matchType = MatchType.COMPARE_EQUAL, responseType = ResponseType.RESOLVED),
                    @Response(text = ResponseNames.FAILURE, field = RETURN_CODE, value = FAILURE,
                            matchType = MatchType.COMPARE_EQUAL, responseType = ResponseType.ERROR, isOnFail = true)
            })
    public Map<String, String> execute(@Param(value = DB_SERVER_NAME, required = true) String dbServerName,
                                       @Param(value = DB_TYPE) String dbType,
                                       @Param(value = USERNAME) String username,
                                       @Param(value = PASSWORD, encrypted = true) String password,
                                       @Param(value = INSTANCE) String instance,
                                       @Param(value = DB_PORT) String dbPort,
                                       @Param(value = DATABASE_NAME, required = true) String databaseName,
                                       @Param(value = AUTHENTICATION_TYPE) String authenticationType,
                                       @Param(value = DB_CLASS) String dbClass,
                                       @Param(value = DB_URL) String dbURL,
                                       @Param(value = COMMAND, required = true) String command,
                                       @Param(value = TRUST_ALL_ROOTS) String trustAllRoots,
                                       @Param(value = TRUST_STORE) String trustStore,
                                       @Param(value = TRUST_STORE_PASSWORD) String trustStorePassword,
                                       @Param(value = AUTH_LIBRARY_PATH) String authLibraryPath,
                                       @Param(value = COL_DELIMITER) String colDelimiter,
                                       @Param(value = ROW_DELIMITER) String rowDelimiter,
                                       @Param(value = TIMEOUT) String timeout,
                                       @Param(value = DATABASE_POOLING_PROPERTIES) String databasePoolingProperties,
                                       @Param(value = RESULT_SET_TYPE) String resultSetType,
                                       @Param(value = RESULT_SET_CONCURRENCY) String resultSetConcurrency) {

        dbType = defaultIfEmpty(dbType, ORACLE_DB_TYPE);
        username = defaultIfEmpty(username, EMPTY);
        password = defaultIfEmpty(password, EMPTY);
        instance = defaultIfEmpty(instance, EMPTY);
        authenticationType = defaultIfEmpty(authenticationType, AUTH_SQL);
        trustAllRoots = defaultIfEmpty(trustAllRoots, FALSE);
        trustStore = defaultIfEmpty(trustStore, EMPTY);
        trustStorePassword = defaultIfEmpty(trustStorePassword, EMPTY);
        timeout = defaultIfEmpty(timeout, DEFAULT_TIMEOUT);

        resultSetType = defaultIfEmpty(resultSetType, TYPE_SCROLL_INSENSITIVE);
        resultSetConcurrency = defaultIfEmpty(resultSetConcurrency, CONCUR_READ_ONLY);

        final List<String> preInputsValidation = validateSqlQueryAllRowsInputs(dbServerName, dbType, username, password, instance,
                dbPort, databaseName, authenticationType, command, trustAllRoots, trustStore, trustStorePassword,
                timeout, resultSetType, resultSetConcurrency, authLibraryPath);

        if (!preInputsValidation.isEmpty()) {
            return getFailureResultsMap(StringUtils.join(preInputsValidation, NEW_LINE));
        }
        dbType = getDbType(dbType);

        final SQLInputs sqlInputs = SQLInputs.builder()
                .dbServer(dbServerName)
                .dbType(dbType)
                .username(username)
                .password(password)
                .instance(instance)
                .dbPort(getOrDefaultDBPort(dbPort, dbType))
                .dbName(defaultIfEmpty(databaseName, EMPTY))
                .authenticationType(authenticationType)
                .dbClass(getOrDefaultDBClass(dbClass, dbType))
                .dbUrl(defaultIfEmpty(dbURL, EMPTY))
                .sqlCommand(command)
                .trustAllRoots(toBoolean(trustAllRoots))
                .trustStore(trustStore)
                .trustStorePassword(trustStorePassword)
                .authLibraryPath(authLibraryPath)
                .colDelimiter(defaultIfEmpty(colDelimiter, COMMA_DELIMITER))
                .rowDelimiter(defaultIfEmpty(rowDelimiter, NEW_LINE))
                .timeout(toInteger(timeout))
                .databasePoolingProperties(getOrDefaultDBPoolingProperties(databasePoolingProperties, EMPTY))
                .resultSetType(getResultSetTypeForDbType(resultSetType, dbType))
                .resultSetConcurrency(getResultSetConcurrency(resultSetConcurrency))
                .isNetcool(checkIsNetcool(dbType))
                .build();

        try {
            final String queryResult = SQLQueryAllRowsService.execQueryAllRows(sqlInputs);
            return OutputUtilities.getSuccessResultsMap(queryResult);
        } catch (Exception e) {
            return OutputUtilities.getFailureResultsMap(e);
        }
    }
}
