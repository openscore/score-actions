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

package io.cloudslang.content.abbyy.services;

import io.cloudslang.content.abbyy.constants.ExceptionMsgs;
import io.cloudslang.content.abbyy.constants.MiscConstants;
import io.cloudslang.content.abbyy.constants.OutputNames;
import io.cloudslang.content.abbyy.constants.XmlSchemas;
import io.cloudslang.content.abbyy.entities.inputs.ProcessImageInput;
import io.cloudslang.content.abbyy.entities.others.ExportFormat;
import io.cloudslang.content.abbyy.entities.responses.AbbyyResponse;
import io.cloudslang.content.abbyy.exceptions.AbbyySdkException;
import io.cloudslang.content.abbyy.exceptions.ValidationException;
import io.cloudslang.content.abbyy.http.AbbyyApi;
import io.cloudslang.content.abbyy.validators.*;
import org.apache.commons.io.FilenameUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.file.FileAlreadyExistsException;
import java.util.HashMap;
import java.util.Map;

public class ProcessImageService extends AbbyyService<ProcessImageInput> {

    private final AbbyyResultValidator xmlResultValidator, txtResultValidator, pdfResultValidator;


    public ProcessImageService() throws ParserConfigurationException {
        this(new ProcessImageInputValidator(), null, null, null, new AbbyyApi());
    }


    ProcessImageService(@NotNull AbbyyInputValidator<ProcessImageInput> requestValidator,
                        @Nullable AbbyyResultValidator xmlResultValidator,
                        @Nullable AbbyyResultValidator txtResultValidator,
                        @Nullable AbbyyResultValidator pdfResultValidator,
                        @NotNull AbbyyApi abbyyApi) {
        super(requestValidator, abbyyApi);
        this.xmlResultValidator = xmlResultValidator != null ? xmlResultValidator : new XmlResultValidator(abbyyApi, XmlSchemas.PROCESS_IMAGE);
        this.txtResultValidator = txtResultValidator != null ? txtResultValidator : new TxtResultValidator(abbyyApi);
        this.pdfResultValidator = pdfResultValidator != null ? pdfResultValidator : new PdfResultValidator(abbyyApi);
    }


    @Override
    void handleTaskCompleted(@NotNull ProcessImageInput request, @NotNull AbbyyResponse response,
                             @NotNull Map<String, String> results) throws Exception {
        super.handleTaskCompleted(request, response, results);

        Map<ExportFormat, String> failure = new HashMap<>();
        String result;

        for (ExportFormat exportFormat : request.getExportFormats()) {
            try {
                switch (exportFormat) {
                    case XML:
                        result = getClearTextResult(request, response, ExportFormat.XML, xmlResultValidator);
                        if (result.startsWith(MiscConstants.BOM_CHAR)) {
                            result = result.substring(1);
                        }
                        results.put(OutputNames.XML_RESULT, result);
                        break;
                    case TXT:
                        result = getClearTextResult(request, response, ExportFormat.TXT, txtResultValidator);
                        results.put(OutputNames.TXT_RESULT, result);
                        break;
                    case PDF_SEARCHABLE:
                        result = getBinaryResult(request, response, ExportFormat.PDF_SEARCHABLE, pdfResultValidator);
                        results.put(OutputNames.PDF_URL, result);
                        break;
                }
            } catch (Exception ex) {
                failure.put(exportFormat, ex.toString());
            }
        }

        if (!failure.isEmpty()) {
            StringBuilder errBuilder = new StringBuilder(ExceptionMsgs.ERROR_RETRIEVING_EXPORT_FORMATS);
            for (ExportFormat exportFormat : failure.keySet()) {
                errBuilder.append('\n')
                        .append("For '" + exportFormat.toString() + "': " + failure.get(exportFormat));
            }
            throw new AbbyySdkException(errBuilder.toString());
        }
    }


    private String getClearTextResult(@NotNull ProcessImageInput abbyyInitialRequest, @NotNull AbbyyResponse abbyyPreviousResponse,
                                      @NotNull ExportFormat exportFormat, @NotNull AbbyyResultValidator resultValidator) throws Exception {
        ValidationException validationEx;

        if (abbyyInitialRequest.getExportFormats().size() != abbyyPreviousResponse.getResultUrls().size()) {
            throw new AbbyySdkException(ExceptionMsgs.EXPORT_FORMAT_AND_RESULT_URLS_DO_NOT_MATCH);
        }
        int indexOfResultUrl = abbyyInitialRequest.getExportFormats().indexOf(exportFormat);
        String resultUrl = abbyyPreviousResponse.getResultUrls().get(indexOfResultUrl);

        validationEx = resultValidator.validateBeforeDownload(abbyyInitialRequest, resultUrl);
        if (validationEx != null) {
            throw validationEx;
        }

        String result = this.abbyyApi.getResult(abbyyInitialRequest, resultUrl, exportFormat, null, true);

        validationEx = resultValidator.validateAfterDownload(result);
        if (validationEx != null) {
            throw validationEx;
        }

        if (abbyyInitialRequest.getDestinationFile() != null) {
            saveClearTextOnDisk(abbyyInitialRequest, result, exportFormat);
        }

        return result;
    }


    private String getBinaryResult(@NotNull ProcessImageInput abbyyInitialRequest, @NotNull AbbyyResponse abbyyPreviousResponse,
                                   @NotNull ExportFormat exportFormat, @NotNull AbbyyResultValidator resultValidator) throws Exception {
        ValidationException validationEx;

        if (abbyyInitialRequest.getExportFormats().size() != abbyyPreviousResponse.getResultUrls().size()) {
            throw new AbbyySdkException(ExceptionMsgs.EXPORT_FORMAT_AND_RESULT_URLS_DO_NOT_MATCH);
        }
        int indexOfResultUrl = abbyyInitialRequest.getExportFormats().indexOf(exportFormat);
        String resultUrl = abbyyPreviousResponse.getResultUrls().get(indexOfResultUrl);

        validationEx = resultValidator.validateBeforeDownload(abbyyInitialRequest, resultUrl);
        if (validationEx != null) {
            throw validationEx;
        }

        if (abbyyInitialRequest.getDestinationFile() != null) {
            String targetPath = downloadOnDisk(abbyyInitialRequest, resultUrl, exportFormat);
            validationEx = resultValidator.validateAfterDownload(targetPath);
            if (validationEx != null) {
                throw validationEx;
            }
        }

        return resultUrl;
    }


    private void saveClearTextOnDisk(@NotNull ProcessImageInput request, @NotNull String clearText,
                                     @NotNull ExportFormat exportFormat) throws IOException {
        String targetPath = getTargetPath(request, exportFormat);
        if (new File(targetPath).exists()) {
            throw new FileAlreadyExistsException(targetPath);
        }
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(targetPath), request.getResponseCharacterSet())) {
            writer.write(clearText);
        }
    }


    private String downloadOnDisk(ProcessImageInput abbyyInitialRequest, String downloadUrl, ExportFormat exportFormat) throws Exception {
        String targetPath = getTargetPath(abbyyInitialRequest, exportFormat);
        if (new File(targetPath).exists()) {
            throw new FileAlreadyExistsException(targetPath);
        }
        this.abbyyApi.getResult(abbyyInitialRequest, downloadUrl, exportFormat, getTargetPath(abbyyInitialRequest, exportFormat), false);
        return targetPath;
    }


    private String getTargetPath(@NotNull ProcessImageInput request, @NotNull ExportFormat exportFormat) {
        return request.getDestinationFile().getAbsolutePath() + "/" +
                FilenameUtils.removeExtension(request.getSourceFile().getName()) + "." +
                exportFormat.getFileExtension();
    }
}