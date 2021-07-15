/*
 * (c) Copyright 2017 EntIT Software LLC, a Micro Focus company, L.P.
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

package io.cloudslang.content.database.services.databases;

import io.cloudslang.content.database.utils.SQLInputs;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import static junit.framework.Assert.assertEquals;
import static org.apache.commons.lang3.StringUtils.EMPTY;

public class VerticaDatabaseTest {

    private static final String DB_NAME = "dbName";
    private static final String DB_SERVER = "dbServer";
    private static final int DB_PORT = 5433;
    private static final String DB_SERVER_IPV6_LITERAL = "2001-0db8-85a3-0042-1000-8a2e-0370-7334.ipv6-literal.net";

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testSetUpNoDbName() throws ClassNotFoundException, SQLException {
        VerticaDatabase verticaDatabase = new VerticaDatabase();
        final SQLInputs sqlInputs = SQLInputs.builder().build();
        sqlInputs.setDbName(EMPTY);
        sqlInputs.setDbServer(DB_SERVER);
        sqlInputs.setDbPort(DB_PORT);
//        sqlInputs.setDbUrls(new ArrayList<String>());

        final List<String> dbUrls = verticaDatabase.setUp(sqlInputs);
        assertEquals("jdbc:vertica://dbServer:5433", dbUrls.get(0));
        assertEquals(1, dbUrls.size());
    }

    @Test
    public void testSetUpNoServerName() throws ClassNotFoundException, SQLException {
        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("host   not valid");
        VerticaDatabase verticaDatabase = new VerticaDatabase();
        final SQLInputs sqlInputs = SQLInputs.builder().build();
        sqlInputs.setDbName(DB_NAME);
        sqlInputs.setDbServer(null);
        sqlInputs.setDbPort(DB_PORT);
//        sqlInputs.setDbUrls(new ArrayList<String>());
        verticaDatabase.setUp(sqlInputs);
    }

    @Test
    public void testSetUpAll() throws ClassNotFoundException, SQLException {
        VerticaDatabase verticaDatabase = new VerticaDatabase();
        final SQLInputs sqlInputs = SQLInputs.builder().build();
        sqlInputs.setDbName(DB_NAME);
        sqlInputs.setDbServer(DB_SERVER);
        sqlInputs.setDbPort(DB_PORT);
//        sqlInputs.setDbUrls(new ArrayList<String>());
        final List<String> dbUrls = verticaDatabase.setUp(sqlInputs);

        assertEquals("jdbc:vertica://dbServer:5433/dbName", dbUrls.get(0));
        assertEquals(1, dbUrls.size());
    }

    @Test
    public void testSetUpAllIPV6LIteral() throws ClassNotFoundException, SQLException {
        VerticaDatabase verticaDatabase = new VerticaDatabase();
        final SQLInputs sqlInputs = SQLInputs.builder().build();
        sqlInputs.setDbName(DB_NAME);
        sqlInputs.setDbServer(DB_SERVER_IPV6_LITERAL);
        sqlInputs.setDbPort(DB_PORT);
//        sqlInputs.setDbUrls(new ArrayList<String>());
        final List<String> dbUrls = verticaDatabase.setUp(sqlInputs);

        assertEquals("jdbc:vertica://2001-0db8-85a3-0042-1000-8a2e-0370-7334.ipv6-literal.net:5433/dbName", dbUrls.get(0));
        assertEquals(1, dbUrls.size());
    }
}
