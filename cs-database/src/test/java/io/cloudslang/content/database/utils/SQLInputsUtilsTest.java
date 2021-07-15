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

import com.hp.oo.sdk.content.plugin.GlobalSessionObject;
import io.cloudslang.content.database.services.databases.*;
import org.jetbrains.annotations.NotNull;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.sql.ResultSet;
import java.util.*;

import static io.cloudslang.content.database.constants.DBOtherValues.*;
import static io.cloudslang.content.database.services.dbconnection.DBConnectionManager.DBType.*;
import static io.cloudslang.content.database.utils.SQLInputsUtils.*;
import static org.apache.commons.lang3.StringUtils.EMPTY;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.mockito.BDDMockito.given;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.verifyStatic;

/**
 * Created by victor on 02.02.2017.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(SQLUtils.class)
public class SQLInputsUtilsTest {


    @Test
    public void checkIsNetcoolTrue() throws Exception {
        assertTrue(checkIsNetcool(NETCOOL_DB_TYPE));
    }

    @Test
    public void checkIsNetcoolFalse() throws Exception {
        assertFalse(checkIsNetcool(MSSQL_DB_TYPE));
        assertFalse(checkIsNetcool(MYSQL_DB_TYPE));
        assertFalse(checkIsNetcool(ORACLE_DB_TYPE));
        assertFalse(checkIsNetcool(CUSTOM_DB_TYPE));
    }

    @Test
    public void getOrDefaultDBClassEmpty() throws Exception {
        assertThat(getOrDefaultDBClass(EMPTY, ORACLE_DB_TYPE), is(ORACLE_JDBC_DRIVER));

    }

    @Test
    public void getOrDefaultDBClassEmptyDbType() throws Exception {
        assertThat(getOrDefaultDBClass(EMPTY, EMPTY), is(EMPTY));
    }

    @Test
    public void getOrDefaultDBClassDefault() throws Exception {
       assertThat(getOrDefaultDBClass("a", ORACLE_DB_TYPE), is("a"));
    }

    //GlobalSessionObject was implemented
    //In CloudSlang the object is instantiated by default and cannot be null
    @Test
    @Ignore
    public void getOrDefaultGlobalSessionObjNull() throws Exception {
        final GlobalSessionObject<Map<String, Object>> globalSessionObj = getOrDefaultGlobalSessionObj(null);
        assertThat(globalSessionObj, instanceOf(GlobalSessionObject.class));
        assertThat(globalSessionObj.get(), instanceOf(Map.class));
    }

    @Test
    public void getOrDefaultGlobalSessionObjNotNull() throws Exception {
        final GlobalSessionObject<Map<String, Object>> validGlobalSessionObj = new GlobalSessionObject<>();
        final SQLSessionResource sqlSessionResource = new SQLSessionResource(new HashMap<String, Object>());
        validGlobalSessionObj.setResource(sqlSessionResource);

        final GlobalSessionObject<Map<String, Object>> globalSessionObj = getOrDefaultGlobalSessionObj(validGlobalSessionObj);

        assertThat(globalSessionObj, is(validGlobalSessionObj));
        assertThat(globalSessionObj.get(), instanceOf(Map.class));
        sqlSessionResource.release();
    }

    @Test
    public void getOrLowerTrue() throws Exception {
        assertThat(getOrLower("AnA", true), is("ana"));
        assertThat(getOrLower("A 2N 1A", true), is("a 2n 1a"));
        assertThat(getOrLower(EMPTY, true), is(EMPTY));
        assertThat(getOrLower("tHis iS a shoRt stoRy!", true), is("this is a short story!"));
    }

    @Test
    public void getOrLowerFalse() throws Exception {
        assertThat(getOrLower("AnA", false), is("AnA"));
        assertThat(getOrLower("A 2N 1A", false), is("A 2N 1A"));
        assertThat(getOrLower(EMPTY, false), is(EMPTY));
        assertThat(getOrLower("tHis iS a shoRt stoRy!", false), is("tHis iS a shoRt stoRy!"));
    }

    @Test
    public void getOrDefaultDBPortEmptyForDBType() throws Exception {
        assertEquals(DEFAULT_PORT_ORACLE.intValue(), getOrDefaultDBPort(EMPTY, ORACLE_DB_TYPE));
        assertEquals(DEFAULT_PORT_MSSQL.intValue(), getOrDefaultDBPort(EMPTY, MSSQL_DB_TYPE));
        assertEquals(DEFAULT_PORT_MYSQL.intValue(), getOrDefaultDBPort(EMPTY, MYSQL_DB_TYPE));
        assertEquals(DEFAULT_PORT_PSQL.intValue(), getOrDefaultDBPort(EMPTY, POSTGRES_DB_TYPE));
        assertEquals(DEFAULT_PORT_VERTICA.intValue(), getOrDefaultDBPort(EMPTY, VERTICA_DB_TYPE));
        assertEquals(DEFAULT_PORT_SYBASE.intValue(), getOrDefaultDBPort(EMPTY, SYBASE_DB_TYPE));
        assertEquals(DEFAULT_PORT_DB2.intValue(), getOrDefaultDBPort(EMPTY, DB2_DB_TYPE));
        assertEquals(DEFAULT_PORT_NETCOOL.intValue(), getOrDefaultDBPort(EMPTY, NETCOOL_DB_TYPE));
    }

    @Test
    public void getOrDefaultDBPortSimple() throws Exception {
        assertEquals(1234, getOrDefaultDBPort("1234", ORACLE_DB_TYPE));
        assertEquals(4321, getOrDefaultDBPort("4321", EMPTY));
    }

    @Test
    public void getOrDefaultDBPortInvalid() throws Exception {
        assertEquals(-1, getOrDefaultDBPort(EMPTY, EMPTY));
    }

    @Test
    public void getSqlCommandsInvalid() throws Exception {
        assertTrue(getSqlCommands(EMPTY, EMPTY, EMPTY).isEmpty());
        assertTrue(getSqlCommands(null, null, ", ").isEmpty());
        assertTrue(getSqlCommands(null, null, null).isEmpty());
    }

    @Test
    public void getSqlCommandsCommandStr() throws Exception {
        assertThat(Arrays.asList("a", "b", "c", "d", "e", "f", "g"), is(getSqlCommands("a,b,c,d,e,f,g", EMPTY, ",")));
        assertThat(Collections.<String>emptyList(), is(getSqlCommands(EMPTY, EMPTY, ",")));
        assertThat(Collections.singletonList("a,b,c,d,e,f,g"), is(getSqlCommands("a,b,c,d,e,f,g", EMPTY, "|")));
    }

    @Test
    public void getSqlCommandsScriptFile() throws Exception {
        final List<String> commandsScript = Arrays.asList("a", "b", "c", "d", "e", "f", "g");
        final String scriptName = "someFile";
        mockStatic(SQLUtils.class);

        given(SQLUtils.readFromFile(scriptName)).willReturn(commandsScript);
        assertThat(commandsScript, is(getSqlCommands(EMPTY, scriptName, ",")));
        verifyStatic();
    }

    @Test
    public void getDbUrlsValid() throws Exception {
        final List<String> dbUrls = getDbUrls("www.google.com");
        assertEquals(1, dbUrls.size());
        assertEquals("www.google.com", dbUrls.get(0));
    }

    @Test
    public void getDbUrlsEmpty() throws Exception {
        assertEquals(0, getDbUrls(EMPTY).size());
        assertEquals(0, getDbUrls(null).size());
    }

    @Test
    public void getOrDefaultDBPoolingPropertiesSimple() throws Exception {
        final Properties dbProperties1 = getOrDefaultDBPoolingProperties("Truth = Beauty", EMPTY);
        assertThat("Beauty", is(dbProperties1.getProperty("Truth")));
        assertThat(1, is(dbProperties1.size()));

        final Properties dbProperties2 = getOrDefaultDBPoolingProperties(" fruits       " +
                "       apple, banana, pear, \\\n" +
                "       cantaloupe, watermelon, \\\n" +
                "       kiwi, mango", EMPTY);
        assertThat("apple, banana, pear, cantaloupe, watermelon, kiwi, mango", is(dbProperties2.getProperty("fruits")));
        assertThat(1, is(dbProperties2.size()));
    }

    @Test
    public void getOrDefaultDBPoolingPropertiesDefault() throws Exception {
        final Properties dbProperties = getOrDefaultDBPoolingProperties(EMPTY, "Truth = Beauty");
        assertThat("Beauty", is(dbProperties.getProperty("Truth")));
        assertThat(1, is(dbProperties.size()));
    }

    //    @Test(expected = RuntimeException.class)
    @Test
    public void getOrDefaultDBPoolingPropertiesException() throws Exception {
//todo
//        final Properties databasePoolingProperties = mock(Properties.class);
//
//        whenNew(Properties.class).withNoArguments().thenReturn(databasePoolingProperties);
////        doReturn(databasePoolingProperties).when(Properties.class).newInstance();
//        doThrow(IllegalArgumentException.class).when(databasePoolingProperties).load(any(Reader.class));
//        getOrDefaultDBPoolingProperties(EMPTY, "this should fail");
    }

    @Test
    public void getResultSetConcurrencySimple() throws Exception {
        assertEquals(ResultSet.CONCUR_READ_ONLY, getResultSetConcurrency(CONCUR_READ_ONLY));
        assertEquals(ResultSet.CONCUR_UPDATABLE, getResultSetConcurrency(CONCUR_UPDATABLE));
    }

    @Test
    public void getResultSetConcurrencyInvalid() throws Exception {
        assertEquals(-1000000, getResultSetConcurrency(EMPTY));
        assertEquals(-1000000, getResultSetConcurrency(null));
        assertEquals(-1000000, getResultSetConcurrency("123"));
    }

    @Test
    public void getResultSetTypeSimple() throws Exception {
        assertEquals(ResultSet.TYPE_FORWARD_ONLY, getResultSetType(TYPE_FORWARD_ONLY));
        assertEquals(ResultSet.TYPE_SCROLL_INSENSITIVE, getResultSetType(TYPE_SCROLL_INSENSITIVE));
        assertEquals(ResultSet.TYPE_SCROLL_SENSITIVE, getResultSetType(TYPE_SCROLL_SENSITIVE));
    }

    @Test
    public void getResultSetTypeInvalid() throws Exception {
        assertEquals(-1000000, getResultSetType(EMPTY));
        assertEquals(-1000000, getResultSetType(null));
        assertEquals(-1000000, getResultSetType("123"));
    }

    @Test
    public void getResultSetTypeForDbTypeDB2() throws Exception {
        assertEquals(ResultSet.TYPE_FORWARD_ONLY, getResultSetTypeForDbType(null, DB2_DB_TYPE));
        assertEquals(ResultSet.TYPE_FORWARD_ONLY, getResultSetTypeForDbType(EMPTY, DB2_DB_TYPE));
        assertEquals(ResultSet.TYPE_FORWARD_ONLY, getResultSetTypeForDbType(TYPE_SCROLL_INSENSITIVE, DB2_DB_TYPE));
    }

    @Test
    public void getResultSetTypeForDbTypeSimple() throws Exception {
        assertEquals(ResultSet.TYPE_FORWARD_ONLY, getResultSetTypeForDbType(TYPE_FORWARD_ONLY, ORACLE_DB_TYPE));
        assertEquals(ResultSet.TYPE_SCROLL_INSENSITIVE, getResultSetTypeForDbType(TYPE_SCROLL_INSENSITIVE, MYSQL_DB_TYPE));
        assertEquals(ResultSet.TYPE_SCROLL_SENSITIVE, getResultSetTypeForDbType(TYPE_SCROLL_SENSITIVE, MSSQL_DB_TYPE));
    }

    @Test
    public void getResultSetTypeForDbTypeInvalid() throws Exception {
        assertEquals(-1000000, getResultSetTypeForDbType(EMPTY, EMPTY));
        assertEquals(-1000000, getResultSetTypeForDbType(null, null));
        assertEquals(-1000000, getResultSetTypeForDbType("123", "123"));

    }

    @Test
    public void notInCollectionIgnoreCaseTrue() throws Exception {
        assertTrue(notInCollectionIgnoreCase("1", Arrays.asList("a", "b", "c")));
        assertTrue(notInCollectionIgnoreCase("2", Collections.<String>emptyList()));
        assertTrue(notInCollectionIgnoreCase("1", Collections.<String>emptySet()));
    }

    @Test
    public void notInCollectionIgnoreCaseFalse() throws Exception {
        assertFalse(notInCollectionIgnoreCase("1", Arrays.asList("a", "1", "c")));
        assertFalse(notInCollectionIgnoreCase("A", Arrays.asList("a", "1", "c")));
        assertFalse(notInCollectionIgnoreCase("C", Arrays.asList("a", "1", "c")));
    }

    @Test
    public void inCollectionIgnoreCaseTrue() throws Exception {
        assertTrue(inCollectionIgnoreCase("1", Arrays.asList("a", "1", "c")));
        assertTrue(inCollectionIgnoreCase("A", Arrays.asList("a", "1", "c")));
        assertTrue(inCollectionIgnoreCase("C", Arrays.asList("a", "1", "c")));
    }

    @Test
    public void inCollectionIgnoreCaseFalse() throws Exception {
        assertFalse(inCollectionIgnoreCase("1", Arrays.asList("a", "b", "c")));
        assertFalse(inCollectionIgnoreCase("2", Collections.<String>emptyList()));
        assertFalse(inCollectionIgnoreCase("1", Collections.<String>emptySet()));
    }

    @Test
    public void getDbTypeSimple() throws Exception {
        assertEquals(ORACLE_DB_TYPE, getDbType("oraCle "));
        assertEquals(MSSQL_DB_TYPE, getDbType("mssql"));
        assertEquals(MYSQL_DB_TYPE, getDbType(" mySqL "));
        assertEquals("1s", getDbType("1s"));
    }

    @Test
    public void getSqlKeyTrue() throws Exception {
        assertThat(getSqlKey(getTestInputsSqlKey(true)), is("SQLQuery:c05adb0bad168df8966ba01a77697005f75ed8bd08815593c5524d6375312ccd"));
    }

    @Test
    public void getSqlKeyFalse() throws Exception {
        assertThat(getSqlKey(getTestInputsSqlKey(false)), is("SQLQuery:8835ea6c637a5e1b67bf01952bc9225597ae33ceeaf17e913aae50193c18346d"));
    }

    @Test
    public void getDbClassForTypeSimple() throws Exception {
        assertThat(getDbClassForType(ORACLE_DB_TYPE), instanceOf(OracleDatabase.class));
        assertThat(getDbClassForType(MYSQL_DB_TYPE), instanceOf(MySqlDatabase.class));
        assertThat(getDbClassForType(MSSQL_DB_TYPE), instanceOf(MSSqlDatabase.class));
        assertThat(getDbClassForType(SYBASE_DB_TYPE), instanceOf(SybaseDatabase.class));
        assertThat(getDbClassForType(NETCOOL_DB_TYPE), instanceOf(NetcoolDatabase.class));
        assertThat(getDbClassForType(POSTGRES_DB_TYPE), instanceOf(PostgreSqlDatabase.class));
        assertThat(getDbClassForType(VERTICA_DB_TYPE), instanceOf(VerticaDatabase.class));
        assertThat(getDbClassForType(DB2_DB_TYPE), instanceOf(DB2Database.class));
        assertThat(getDbClassForType(CUSTOM_DB_TYPE), instanceOf(CustomDatabase.class));
    }

    @Test(expected = RuntimeException.class)
    public void getDbClassForTypeFailure() throws Exception {
        getDbClassForType("NoType");
    }

    @Test
    public void getDbEnumForTypeSimple() throws Exception {
        assertThat(getDbEnumForType(ORACLE_DB_TYPE), is(ORACLE));
        assertThat(getDbEnumForType(MYSQL_DB_TYPE), is(MYSQL));
        assertThat(getDbEnumForType(MSSQL_DB_TYPE), is(MSSQL));
        assertThat(getDbEnumForType(SYBASE_DB_TYPE), is(SYBASE));
        assertThat(getDbEnumForType(NETCOOL_DB_TYPE), is(NETCOOL));
        assertThat(getDbEnumForType(VERTICA_DB_TYPE), is(VERTICA));
        assertThat(getDbEnumForType(DB2_DB_TYPE), is(DB2));
        assertThat(getDbEnumForType(CUSTOM_DB_TYPE), is(CUSTOM));
    }


    @Test(expected = RuntimeException.class)
    public void getDbEnumForTypeFailure() throws Exception {
        getDbEnumForType("NoType");
    }

    @NotNull
    private SQLInputs getTestInputsSqlKey(boolean ignoreCase) {
        final SQLInputs sqlInputs = SQLInputs.builder().build();
        sqlInputs.setIgnoreCase(ignoreCase);
        sqlInputs.setInstance("INSTANCE");
        sqlInputs.setDbName("DBNAME");
        sqlInputs.setDbServer("DBSERVER");
        sqlInputs.setDbType("DBTYPE");
        sqlInputs.setUsername("USERNAME");
        sqlInputs.setPassword("PASSWORD");
        sqlInputs.setDbPort(123);
        sqlInputs.setDbName("DBNAME");
        sqlInputs.setAuthenticationType("AUTHTYPE");
        sqlInputs.setSqlCommand("SQLCOMMAND");

        return sqlInputs;
    }

}
