/*
 * (c) Copyright 2020 EntIT Software LLC, a Micro Focus company, L.P.
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
package io.cloudslang.content.abbyy.validators;

import io.cloudslang.content.abbyy.exceptions.ValidationException;
import io.cloudslang.content.abbyy.http.AbbyyRequest;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.File;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;

@RunWith(PowerMockRunner.class)
public abstract class AbbyyRequestValidatorTest<R extends AbbyyRequest> {

    AbbyyRequestValidator<R> sut;
    @Rule
    public ExpectedException exception = ExpectedException.none();


    @Before
    public void setUp() {
        this.sut = newSutInstance();
    }


    @Test
    public void validate_locationIdIsNull_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getLocationId()).thenReturn(null);
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_applicationIdIsBlank_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getApplicationId()).thenReturn(" ");
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_passwordIsBlank_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getPassword()).thenReturn(" ");
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_proxyPortIsNegativeAndNotMinusOne_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getProxyPort()).thenReturn((short) -2);
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_proxyPortIsMinusOne_nullReturned() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getProxyPort()).thenReturn((short) -1);
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNull(ex);
    }


    @Test
    public void validate_connectTimeoutIsNegative_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getConnectTimeout()).thenReturn(-1);
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_socketTimeoutIsNegative_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getSocketTimeout()).thenReturn(-1);
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_connectionsMaxPerRouteIsNegative_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getConnectionsMaxPerRoute()).thenReturn(-1);
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_connectionsMaxTotalIsNegative_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getConnectionsMaxTotal()).thenReturn(-1);
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_destinationFileIsNull_nullReturned() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getDestinationFile()).thenReturn(null);
        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);
        //Assert
        assertNull(ex);
    }


    @Test
    public void validate_destinationFileAlreadyExists_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();

        File destinationFileMock = mock(File.class);
        when(destinationFileMock.exists()).thenReturn(true);
        when(abbyyRequestMock.getDestinationFile()).thenReturn(destinationFileMock);

        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);

        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_destinationFileParentDoesNotExist_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();

        File destinationFolderMock = mock(File.class);
        when(destinationFolderMock.exists()).thenReturn(false);

        File destinationFileMock = mock(File.class);
        when(destinationFileMock.exists()).thenReturn(true);
        when(destinationFileMock.getParentFile()).thenReturn(destinationFolderMock);

        when(abbyyRequestMock.getDestinationFile()).thenReturn(destinationFileMock);

        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);

        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_sourceFileIsNull_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();
        when(abbyyRequestMock.getSourceFile()).thenReturn(null);

        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);

        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_sourceFileDoesNotExist_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();

        File sourceFileMock = mock(File.class);
        when(sourceFileMock.exists()).thenReturn(false);
        when(abbyyRequestMock.getSourceFile()).thenReturn(sourceFileMock);

        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);

        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_sourceFileIsNotFile_ValidationException() {
        //Arrange
        R abbyyRequestMock = mockAbbyyRequest();

        File sourceFileMock = mock(File.class);
        when(sourceFileMock.exists()).thenReturn(true);
        when(sourceFileMock.isFile()).thenReturn(false);
        when(abbyyRequestMock.getSourceFile()).thenReturn(sourceFileMock);

        //Act
        ValidationException ex = this.sut.validate(abbyyRequestMock);

        //Assert
        assertNotNull(ex);
    }


    @Test
    public void validate_validRequest_nullReturned() {
        //Arrange
        R request = mockAbbyyRequest();
        AbbyyRequestValidator<R> sut = mock(this.sut.getClass());
        doCallRealMethod().when(sut).validate(eq(request));
        //Act
        ValidationException ex = sut.validate(request);
        //Assert
        assertNull(ex);
    }


    abstract AbbyyRequestValidator<R> newSutInstance();

    abstract R mockAbbyyRequest();
}
