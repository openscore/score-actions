/*
 * (c) Copyright 2017 Hewlett-Packard Development Company, L.P.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0 which accompany this distribution.
 *
 * The Apache License is available at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
*/
package io.cloudslang.content.database.actions;

import io.cloudslang.content.database.services.SQLCommandService;
import io.cloudslang.content.database.utils.SQLInputs;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.Map;

import static io.cloudslang.content.constants.OutputNames.RETURN_CODE;
import static io.cloudslang.content.constants.OutputNames.RETURN_RESULT;
import static io.cloudslang.content.constants.ReturnCodes.FAILURE;
import static io.cloudslang.content.constants.ReturnCodes.SUCCESS;
import static io.cloudslang.content.database.constants.DBDefaultValues.AUTH_SQL;
import static io.cloudslang.content.database.constants.DBOtherValues.*;
import static io.cloudslang.content.database.constants.DBOutputNames.OUTPUT_TEXT;
import static org.apache.commons.lang3.StringUtils.EMPTY;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.powermock.api.mockito.PowerMockito.*;

/**
 * Created by victor on 13.02.2017.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({SQLCommand.class, SQLCommandService.class})
public class SQLCommandTest {

    @Spy
    private final SQLCommand sqlCommand = new SQLCommand();

    @Test
    public void execute() throws Exception {
        final Map<String, String> resultMap = new SQLCommand().execute(EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY,
                EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, EMPTY);
        assertThat(resultMap.get(RETURN_CODE), is(FAILURE));
        assertThat(resultMap.get(RETURN_RESULT), is("dbServerName can't be empty\nusername input is empty.\npassword input is empty.\ndatabase input is empty.\ncommand input is empty."));
    }

    @Test
    public void executeSuccess() throws Exception {
        final String res = "result";

        mockStatic(SQLCommandService.class);


        when(SQLCommandService.executeSqlCommand(any(SQLInputs.class))).thenReturn(res);

        final Map<String, String> resultMap = sqlCommand.execute("1", ORACLE_DB_TYPE, "username", "Password", EMPTY, "123", "db",
                AUTH_SQL, EMPTY, EMPTY, DBMS_OUTPUT, EMPTY, TYPE_FORWARD_ONLY, CONCUR_READ_ONLY);

        verifyStatic();
        assertThat(resultMap.get(RETURN_CODE), is(SUCCESS));
        assertThat(resultMap.get(RETURN_RESULT), is("Command completed successfully"));
        assertThat(resultMap.get(OUTPUT_TEXT), is(res));
    }

}