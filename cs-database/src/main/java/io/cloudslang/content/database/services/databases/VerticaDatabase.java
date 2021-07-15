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

import io.cloudslang.content.database.utils.Address;
import io.cloudslang.content.database.utils.SQLInputs;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.util.List;

import static io.cloudslang.content.database.constants.DBOtherValues.FORWARD_SLASH;
import static io.cloudslang.content.database.utils.SQLInputsUtils.getDbUrls;
import static io.cloudslang.content.database.utils.SQLUtils.loadClassForName;

/**
 * Created by stefan on 11.05.2018.
 */
public class VerticaDatabase implements SqlDatabase {

    @Override
    public List<String> setUp(@NotNull final SQLInputs sqlInputs) {
        loadClassForName("com.vertica.jdbc.Driver");
        final String connectionString = getConnectionString(sqlInputs);
        final List<String> dbUrls = getDbUrls(sqlInputs.getDbUrl());
        dbUrls.add(connectionString);
        return dbUrls;
    }

    private String getConnectionString(final SQLInputs sqlInputs) {
        final Address address = new Address(sqlInputs.getDbServer());
        final StringBuilder connectionSb = new StringBuilder("jdbc:vertica://");
        if (address.isIPV6Literal()) {//the host is an IPv6 literal
            connectionSb.append(String.format("[host=%s]:%d", sqlInputs.getDbServer(), sqlInputs.getDbPort()));
        } else {
            connectionSb.append(String.format("%s:%d", sqlInputs.getDbServer(), sqlInputs.getDbPort()));
        }
        if (StringUtils.isNoneEmpty(sqlInputs.getDbName())) {
            connectionSb.append(FORWARD_SLASH)
                    .append(sqlInputs.getDbName());
        }
        //the host is an IPv4 literal or a Host Name
        return connectionSb.toString();
    }
}
