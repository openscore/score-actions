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



package io.cloudslang.content.database.utils;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static io.cloudslang.content.constants.BooleanValues.FALSE;
import static io.cloudslang.content.database.constants.DBDefaultValues.AUTH_SQL;
import static io.cloudslang.content.database.constants.DBExceptionValues.*;
import static io.cloudslang.content.database.constants.DBOtherValues.*;
import static io.cloudslang.content.database.utils.Constants.AUTH_WINDOWS;
import static io.cloudslang.content.database.utils.SQLInputsValidator.*;
import static org.apache.commons.lang3.StringUtils.EMPTY;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

/**
 * Created by victor on 1/28/17.
 */
public class SQLInputsValidatorTest {
    @Test
    public void validateSqlCommandInputsValid() throws Exception {
        final List<String> validationList = validateSqlCommandInputs("1", MSSQL_DB_TYPE, "username",
                "Password", "someInstance", "123", "database", AUTH_SQL, "Command",
                "true", TYPE_FORWARD_ONLY, CONCUR_READ_ONLY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList, is(Collections.<String>emptyList()));
    }

    @Test
    public void validateSqlCommandInputsEmpty() throws Exception {
        final List<String> validationList1 = validateSqlCommandInputs(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList1, is(Arrays.asList(INVALID_DB_TYPE, INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_COMMAND)));

        final List<String> validationList2 = validateSqlCommandInputs(EMPTY, MYSQL_DB_TYPE, EMPTY, EMPTY, "Instance", EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList2, is(Arrays.asList(INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_INSTANCE, INVALID_DATABASE,
                String.format(INVALID_AUTH_TYPE, EMPTY), INVALID_COMMAND)));

        final List<String> validationList3 = validateSqlCommandInputs(EMPTY, MYSQL_DB_TYPE, EMPTY, EMPTY, "Instance", EMPTY, EMPTY, AUTH_WINDOWS, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList3, is(Arrays.asList(INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_INSTANCE, INVALID_DATABASE,
                INVALID_AUTH_TYPE_WINDOWS, INVALID_COMMAND)));

    }

    @Test
    public void validateSqlQueryInputsValid() throws Exception {
        final List<String> validationList = validateSqlQueryInputs("1", MSSQL_DB_TYPE, "username",
                "Password", "someInstance", "123", "database", AUTH_SQL, "Command", "true", EMPTY, EMPTY, "1", TYPE_FORWARD_ONLY, CONCUR_READ_ONLY, FALSE, EMPTY);
        assertThat(validationList, is(Collections.<String>emptyList()));
    }

    @Test
    public void validateSqlQueryInputsEmpty() throws Exception {
        final List<String> validationList1 = validateSqlQueryInputs(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList1, is(Arrays.asList(INVALID_DB_TYPE, INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, String.format(INVALID_IGNORE_CASE, EMPTY),
                INVALID_COMMAND, INVALID_TIMEOUT)));

        final List<String> validationList2 = validateSqlQueryInputs(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, "1a12a", EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList2, is(Arrays.asList(INVALID_DB_TYPE, INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_DB_PORT, String.format(INVALID_IGNORE_CASE, EMPTY),
                INVALID_COMMAND, INVALID_TIMEOUT)));
    }

    @Test
    public void validateSqlQueryAllRowsInputsValid() throws Exception {
        final List<String> validationList = validateSqlQueryAllRowsInputs("1", MSSQL_DB_TYPE, "username",
                "Password", "someInstance", "123", "database", AUTH_SQL, "Command", "true", EMPTY, EMPTY,
                "1", TYPE_FORWARD_ONLY, CONCUR_READ_ONLY, EMPTY);
        assertThat(validationList, is(Collections.<String>emptyList()));
    }

    @Test
    public void validateSqlQueryAllRowsInputsEmpty() throws Exception {
        final List<String> validationList1 = validateSqlQueryAllRowsInputs(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList1, is(Arrays.asList(INVALID_DB_TYPE, INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_COMMAND, INVALID_TIMEOUT)));

        final List<String> validationList2 = validateSqlQueryAllRowsInputs(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, "-1", EMPTY, EMPTY, EMPTY);
        assertThat(validationList2, is(Arrays.asList(INVALID_DB_TYPE, INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_COMMAND, INVALID_NEGATIVE_TIMEOUT)));
    }

    @Test
    public void validateSqlQueryLOBInputsValid() throws Exception {
        final List<String> validationList = validateSqlQueryLOBInputs("1", MSSQL_DB_TYPE, "username",
                "Password", "someInstance", "123", "database", AUTH_SQL, "Command", "true", EMPTY, EMPTY, "1", TYPE_FORWARD_ONLY, CONCUR_READ_ONLY, EMPTY);
        assertThat(validationList, is(Collections.<String>emptyList()));
    }

    @Test
    public void validateSqlQueryLOBInputsEmpty() throws Exception {
        final List<String> validationList1 = validateSqlQueryLOBInputs(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList1, is(Arrays.asList(INVALID_DB_TYPE, INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_COMMAND, INVALID_TIMEOUT)));
    }

    @Test
    public void validateSqlQueryTabularInputsValid() throws Exception {
        final List<String> validationList = validateSqlQueryTabularInputs("1", MSSQL_DB_TYPE, "username",
                "Password", "someInstance", "123", "database", AUTH_SQL, "Command", "true", EMPTY, EMPTY,
                "1", TYPE_FORWARD_ONLY, CONCUR_READ_ONLY, EMPTY);
        assertThat(validationList, is(Collections.<String>emptyList()));
    }

    @Test
    public void validateSqlQueryTabularInputsEmpty() throws Exception {
        final List<String> validationList1 = validateSqlQueryTabularInputs(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList1, is(Arrays.asList(INVALID_DB_TYPE, INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_COMMAND, INVALID_TIMEOUT)));
    }

    @Test
    public void validateSqlScriptInputsValid() throws Exception {
        final List<String> validationList = validateSqlScriptInputs("1", MSSQL_DB_TYPE, "username",
                "Password", "someInstance", "123", "database", AUTH_SQL, "Commands", EMPTY, "true", EMPTY, EMPTY, TYPE_FORWARD_ONLY, CONCUR_READ_ONLY, EMPTY);
        assertThat(validationList, is(Collections.<String>emptyList()));
    }

    @Test
    public void validateSqlScriptInputsEmpty() throws Exception {
        final List<String> validationList1 = validateSqlScriptInputs(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(validationList1, is(Arrays.asList(INVALID_DB_TYPE, INVALID_DB_SERVER_NAME, INVALID_USERNAME, INVALID_PASSWORD, INVALID_TRUST_ALL_ROOTS,
                INVALID_RESULT_SET_TYPE, INVALID_RESULT_SET_CONCURRENCY, INVALID_COMMANDS_EXCLUSIVITY)));

    }

    @Test
    public void isValidAuthTypeValid() throws Exception {
        assertTrue(isValidAuthType(AUTH_WINDOWS));
        assertTrue(isValidAuthType(AUTH_SQL));
    }

    @Test
    public void isValidAuthTypeInvalid() throws Exception {
        assertFalse(isValidAuthType(EMPTY));
        assertFalse(isValidAuthType("123"));
    }

    @Test
    public void isNotValidAuthTypeValid() throws Exception {
        assertTrue(isNotValidAuthType(EMPTY));
        assertTrue(isNotValidAuthType("123"));
    }

    @Test
    public void isNotValidAuthTypeInvalid() throws Exception {
        assertFalse(isNotValidAuthType(AUTH_WINDOWS));
        assertFalse(isNotValidAuthType(AUTH_SQL));
    }

    @Test
    public void isValidDbTypeValid() throws Exception {
        assertTrue(isValidDbType(ORACLE_DB_TYPE));
        assertTrue(isValidDbType(MSSQL_DB_TYPE));
        assertTrue(isValidDbType(SYBASE_DB_TYPE));
        assertTrue(isValidDbType(NETCOOL_DB_TYPE));
        assertTrue(isValidDbType(DB2_DB_TYPE));
        assertTrue(isValidDbType(MYSQL_DB_TYPE));
        assertTrue(isValidDbType(POSTGRES_DB_TYPE));
        assertTrue(isValidDbType(VERTICA_DB_TYPE));
        assertTrue(isValidDbType(CUSTOM_DB_TYPE));
    }

    @Test
    public void isValidDbTypeInvalid() throws Exception {
        assertFalse(isValidDbType(EMPTY));
        assertFalse(isValidDbType("123"));
    }

    @Test
    public void isNotValidDbTypeValid() throws Exception {
        assertTrue(isNotValidDbType(EMPTY));
        assertTrue(isNotValidDbType("123"));
    }

    @Test
    public void isNotValidDbTypeInvalid() throws Exception {
        assertFalse(isNotValidDbType(ORACLE_DB_TYPE));
        assertFalse(isNotValidDbType(MSSQL_DB_TYPE));
        assertFalse(isNotValidDbType(SYBASE_DB_TYPE));
        assertFalse(isNotValidDbType(NETCOOL_DB_TYPE));
        assertFalse(isNotValidDbType(DB2_DB_TYPE));
        assertFalse(isNotValidDbType(MYSQL_DB_TYPE));
        assertFalse(isNotValidDbType(POSTGRES_DB_TYPE));
        assertFalse(isNotValidDbType(VERTICA_DB_TYPE));
        assertFalse(isNotValidDbType(CUSTOM_DB_TYPE));
    }

    @Test
    public void isValidResultSetConcurrencyValid() throws Exception {
        assertTrue(isValidResultSetConcurrency(CONCUR_READ_ONLY));
        assertTrue(isValidResultSetConcurrency(CONCUR_UPDATABLE));
    }

    @Test
    public void isValidResultSetConcurrencyInvalid() throws Exception {
        assertFalse(isValidResultSetConcurrency("123"));
        assertFalse(isValidResultSetConcurrency(EMPTY));
    }

    @Test
    public void isValidResultSetTypeValid() throws Exception {
        assertTrue(isValidResultSetType(TYPE_FORWARD_ONLY));
        assertTrue(isValidResultSetType(TYPE_SCROLL_INSENSITIVE));
        assertTrue(isValidResultSetType(TYPE_SCROLL_SENSITIVE));
    }

    @Test
    public void isValidResultSetTypeInvalid() throws Exception {
        assertFalse(isValidResultSetType("123"));
        assertFalse(isValidResultSetConcurrency(EMPTY));
    }

}
