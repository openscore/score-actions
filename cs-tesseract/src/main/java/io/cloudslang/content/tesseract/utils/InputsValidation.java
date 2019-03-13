/*
 * (c) Copyright 2019 Micro Focus, L.P.
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
package io.cloudslang.content.tesseract.utils;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static io.cloudslang.content.tesseract.utils.Constants.*;
import static io.cloudslang.content.tesseract.utils.Inputs.*;
import static io.cloudslang.content.utils.BooleanUtilities.isValid;
import static org.apache.commons.lang3.StringUtils.isEmpty;

public class InputsValidation {

    @NotNull
    public static List<String> verifyExtractTextInputs(@Nullable final String filePath,
                                                       @Nullable final String dataPath,
                                                       @Nullable final String textBlocks,
                                                       @Nullable final String deskew) {

        return verifyCommonInputs(filePath, dataPath, textBlocks, deskew);
    }

    @NotNull
    public static List<String> verifyExtractTextFromPDF(@Nullable final String filePath,
                                                        @Nullable final String dataPath,
                                                        @Nullable final String textBlocks,
                                                        @Nullable final String deskew,
                                                        @Nullable final Integer fromPage,
                                                        @Nullable final Integer toPage,
                                                        @Nullable final String pageIndex) {

        final List<String> exceptionMessages = verifyCommonInputs(filePath, dataPath, textBlocks, deskew);

        if (fromPage > toPage)
            exceptionMessages.add(EXCEPTION_INVALID_FROM_PAGE);

        String regex = "[0-9, /,]+";
        final boolean matches = pageIndex.matches(regex);
        if (!matches)
            exceptionMessages.add(EXCEPTION_INVALID_INPUT);

        return exceptionMessages;
    }

    @NotNull
    private static List<String> verifyCommonInputs(@Nullable final String filePath,
                                                   @Nullable final String dataPath,
                                                   @Nullable final String textBlocks,
                                                   @Nullable final String deskew) {

        final List<String> exceptionMessages = new ArrayList<>();
        addVerifyBoolean(exceptionMessages, textBlocks, TEXT_BLOCKS);
        addVerifyBoolean(exceptionMessages, deskew, DESKEW);
        addVerifyFilePath(exceptionMessages, filePath, FILE_PATH);
        addVerifyDataPath(exceptionMessages, dataPath, DATA_PATH);
        return exceptionMessages;
    }

    @NotNull
    private static List<String> addVerifyFilePath(@NotNull List<String> exceptions, @Nullable final String filePath, @NotNull final String inputName) {

        if (isEmpty(filePath)) {
            exceptions.add(EXCEPTION_EMPTY_FILE);
        } else if (!isEmpty(filePath) && !isValidFile(filePath)) {
            exceptions.add(String.format(EXCEPTION_INVALID_FILE, filePath, inputName));
        }
        return exceptions;
    }

    @NotNull
    private static List<String> addVerifyDataPath(@NotNull List<String> exceptions, @Nullable final String dataPath, @NotNull final String inputName) {

        if (!isEmpty(dataPath) && !isValidFile(dataPath))
            exceptions.add(String.format(EXCEPTION_INVALID_DATA_PATH, dataPath, inputName));
        return exceptions;
    }

    @NotNull
    private static List<String> addVerifyBoolean(@NotNull List<String> exceptions, @Nullable final String input, @NotNull final String inputName) {
        if (isEmpty(input)) {
            exceptions.add(String.format(EXCEPTION_NULL_EMPTY, inputName));
        } else if (!isValid(input)) {
            exceptions.add(String.format(EXCEPTION_INVALID_BOOLEAN, input, inputName));
        }
        return exceptions;
    }


    private static boolean isValidFile(@NotNull final String filePath) {
        return new File(filePath).exists();
    }
}
