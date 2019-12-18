/*
 * (c) Copyright 2020 Micro Focus, L.P.
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

package io.cloudslang.content.hashicorp.terraform.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.cloudslang.content.hashicorp.terraform.entities.TerraformCommonInputs;
import io.cloudslang.content.hashicorp.terraform.entities.TerraformVariableInputs;
import io.cloudslang.content.hashicorp.terraform.entities.TerraformWorkspaceInputs;
import io.cloudslang.content.hashicorp.terraform.services.models.variables.CreateVariableRequestBody;
import io.cloudslang.content.httpclient.entities.HttpClientInputs;
import io.cloudslang.content.httpclient.services.HttpClientService;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.apache.http.client.utils.URIBuilder;
import org.jetbrains.annotations.NotNull;

import java.util.HashMap;
import java.util.Map;

import static io.cloudslang.content.hashicorp.terraform.services.HttpCommons.setCommonHttpInputs;
import static io.cloudslang.content.hashicorp.terraform.utils.Constants.Common.*;
import static io.cloudslang.content.hashicorp.terraform.utils.Constants.CreateVariableConstants.VARIABLE_PATH;
import static io.cloudslang.content.hashicorp.terraform.utils.Constants.CreateVariableConstants.VARIABLE_TYPE;
import static io.cloudslang.content.hashicorp.terraform.utils.Constants.CreateWorkspaceConstants.WORKSPACE_TYPE;
import static io.cloudslang.content.hashicorp.terraform.utils.Constants.ListVariableConstants.ORGANIZATION_NAME;
import static io.cloudslang.content.hashicorp.terraform.utils.Constants.ListVariableConstants.WORKSPACE_NAME;
import static io.cloudslang.content.hashicorp.terraform.utils.HttpUtils.getAuthHeaders;
import static io.cloudslang.content.hashicorp.terraform.utils.HttpUtils.getUriBuilder;
import static org.apache.commons.lang3.StringUtils.EMPTY;

public class VariableImpl {

    @NotNull
    public static Map<String, Map<String,String>> createVariable(@NotNull  TerraformVariableInputs terraformVariableInputs,String variablesJson)throws Exception  {
        String variableName;
        String variableValue;
        String hcl;
        String catagory;
        Map<String, Map<String,String>> createVariableMap = new HashMap<>();
        final HttpClientInputs httpClientInputs = new HttpClientInputs();
        final TerraformCommonInputs commonInputs = terraformVariableInputs.getCommonInputs();
        httpClientInputs.setUrl(createVariableUrl());
        setCommonHttpInputs(httpClientInputs, commonInputs);
        httpClientInputs.setAuthType(ANONYMOUS);
        httpClientInputs.setMethod(POST);
        httpClientInputs.setContentType(APPLICATION_VND_API_JSON);
        httpClientInputs.setHeaders(getAuthHeaders(commonInputs.getAuthToken()));
        if (terraformVariableInputs.getSensitiveVariableName().isEmpty() & terraformVariableInputs.getCommonInputs().getRequestBody().isEmpty()) {
                JSONParser parser = new JSONParser();
                JSONArray createVariableJsonArray = (JSONArray) parser.parse(variablesJson);
                JSONObject createVariableJson;
                for (int i = 0; i < createVariableJsonArray.size(); i++) {
                    createVariableJson = (JSONObject) createVariableJsonArray.get(i);
                    variableName = (String) createVariableJson.get("propertyName");
                    variableValue = (String) createVariableJson.get("propertyValue");
                    hcl = Boolean.toString((boolean) createVariableJson.get("HCL"));
                    catagory = (String) createVariableJson.get("Category");

                    System.out.println(catagory);

                    terraformVariableInputs = TerraformVariableInputs.builder()
                            .sensitiveVariableName(variableName)
                            .sensitiveVariableValue(variableValue)
                            .variableCategory(catagory)
                            .hcl(hcl)
                            .workspaceId(terraformVariableInputs.getWorkspaceId())
                            .sensitive("false").build();
                    httpClientInputs.setBody(createVariableRequestBody(terraformVariableInputs));
                    createVariableMap.put(variableName, new HttpClientService().execute(httpClientInputs));

                }

                return createVariableMap;



        } else {

            if (commonInputs.getRequestBody().equals(EMPTY)) {
                httpClientInputs.setBody(createVariableRequestBody(terraformVariableInputs));
            } else {
                httpClientInputs.setBody(commonInputs.getRequestBody());
            }
            httpClientInputs.setResponseCharacterSet(commonInputs.getResponseCharacterSet());
             createVariableMap.put(terraformVariableInputs.getSensitiveVariableName(),new HttpClientService().execute(httpClientInputs));

             return createVariableMap;
        }
    }

    @NotNull
    public static Map<String, String> listVariables(@NotNull final TerraformWorkspaceInputs terraformWorkspaceInputs) throws Exception {
        final HttpClientInputs httpClientInputs = new HttpClientInputs();
        httpClientInputs.setUrl(listVariablesUrl());
        setCommonHttpInputs(httpClientInputs, terraformWorkspaceInputs.getCommonInputs());
        httpClientInputs.setAuthType(ANONYMOUS);
        httpClientInputs.setMethod(GET);
        httpClientInputs.setContentType(APPLICATION_VND_API_JSON);
        httpClientInputs.setQueryParams(getListVariableQueryParams(terraformWorkspaceInputs.getCommonInputs().getOrganizationName(), terraformWorkspaceInputs.getWorkspaceName()));
        httpClientInputs.setResponseCharacterSet(terraformWorkspaceInputs.getCommonInputs().getResponseCharacterSet());
        httpClientInputs.setHeaders(getAuthHeaders(terraformWorkspaceInputs.getCommonInputs().getAuthToken()));
        return new HttpClientService().execute(httpClientInputs);
    }


    @NotNull
    public static String listVariablesUrl() throws Exception {

        final URIBuilder uriBuilder = getUriBuilder();
        StringBuilder pathString = new StringBuilder()
                .append(API)
                .append(API_VERSION)
                .append(VARIABLE_PATH);
        uriBuilder.setPath(pathString.toString());
        return uriBuilder.build().toURL().toString();
    }

    @NotNull
    private static String createVariableUrl() throws Exception {
        final URIBuilder uriBuilder = getUriBuilder();
        uriBuilder.setPath(getVariablePath());
        return uriBuilder.build().toURL().toString();
    }

    @NotNull
    public static String getListVariableQueryParams(String organizationName,
                                                    final String workspaceName) {
        final StringBuilder queryParams = new StringBuilder()
                .append(QUERY)
                .append(ORGANIZATION_NAME)
                .append(organizationName)
                .append(AND)
                .append(WORKSPACE_NAME)
                .append(workspaceName);
        return queryParams.toString();
    }

    @NotNull
    public static String getVariablePath() {
        StringBuilder pathString = new StringBuilder()
                .append(API)
                .append(API_VERSION)
                .append(VARIABLE_PATH);
        return pathString.toString();
    }


    public static Map<String, String> updateVariable(@NotNull final TerraformVariableInputs updateVariableInputs)
            throws Exception {
        final HttpClientInputs httpClientInputs = new HttpClientInputs();
        final TerraformCommonInputs commonInputs = updateVariableInputs.getCommonInputs();
        httpClientInputs.setUrl(updateVariableUrl(updateVariableInputs.getVariableId()));
        setCommonHttpInputs(httpClientInputs, commonInputs);
        httpClientInputs.setAuthType(ANONYMOUS);
        httpClientInputs.setMethod(PATCH);
        httpClientInputs.setContentType(APPLICATION_VND_API_JSON);
        httpClientInputs.setBody(commonInputs.getRequestBody());
        httpClientInputs.setResponseCharacterSet(commonInputs.getResponseCharacterSet());
        httpClientInputs.setHeaders(getAuthHeaders(commonInputs.getAuthToken()));
        return new HttpClientService().execute(httpClientInputs);
    }

    @NotNull
    public static Map<String, String> deleteVariable(@NotNull final TerraformVariableInputs deleteVariableInputs)
            throws Exception {
        final HttpClientInputs httpClientInputs = new HttpClientInputs();
        final TerraformCommonInputs commonInputs = deleteVariableInputs.getCommonInputs();
        httpClientInputs.setUrl(deleteVariableUrl(deleteVariableInputs.getVariableId()));
        setCommonHttpInputs(httpClientInputs, commonInputs);
        httpClientInputs.setAuthType(ANONYMOUS);
        httpClientInputs.setMethod(DELETE);
        httpClientInputs.setContentType(APPLICATION_VND_API_JSON);
        httpClientInputs.setResponseCharacterSet(commonInputs.getResponseCharacterSet());
        httpClientInputs.setHeaders(getAuthHeaders(commonInputs.getAuthToken()));
        return new HttpClientService().execute(httpClientInputs);
    }

    @NotNull
    private static String updateVariableUrl(@NotNull final String variableId) throws Exception {
        final URIBuilder uriBuilder = getUriBuilder();
        uriBuilder.setPath(getVariablePath(variableId));
        return uriBuilder.build().toURL().toString();
    }

    @NotNull
    private static String deleteVariableUrl(@NotNull final String variableId) throws Exception {
        final URIBuilder uriBuilder = getUriBuilder();
        uriBuilder.setPath(getVariablePath(variableId));
        return uriBuilder.build().toURL().toString();
    }

    @NotNull
    public static String getVariablePath(@NotNull final String variableId) {
        StringBuilder pathString = new StringBuilder()
                .append(API)
                .append(API_VERSION)
                .append(VARIABLE_PATH)
                .append(PATH_SEPARATOR)
                .append(variableId);
        return pathString.toString();
    }

    @NotNull
    public static String createVariableRequestBody(TerraformVariableInputs terraformVariableInputs) {
        String requestBody = EMPTY;
        ObjectMapper createVariableMapper = new ObjectMapper();
        CreateVariableRequestBody createVariableRequestBody = new CreateVariableRequestBody();
        CreateVariableRequestBody.CreateVariableData createVariableData = createVariableRequestBody.new CreateVariableData();
        createVariableData.setType(VARIABLE_TYPE);

        CreateVariableRequestBody.Attributes attributes = createVariableRequestBody.new Attributes();
        attributes.setKey(terraformVariableInputs.getSensitiveVariableName());
        attributes.setValue(terraformVariableInputs.getSensitiveVariableValue());
        attributes.setCategory(terraformVariableInputs.getVariableCategory());
        attributes.setHcl(terraformVariableInputs.getHcl());
        attributes.setSensitive(terraformVariableInputs.getSensitive());

        CreateVariableRequestBody.Data data = createVariableRequestBody.new Data();
        data.setId(terraformVariableInputs.getWorkspaceId());
        data.setType(WORKSPACE_TYPE);
        CreateVariableRequestBody.Workspace workspace = createVariableRequestBody.new Workspace();
        workspace.setData(data);
        CreateVariableRequestBody.Relationships relationships = createVariableRequestBody.new Relationships();
        relationships.setWorkspace(workspace);

        createVariableData.setRelationships(relationships);
        createVariableData.setAttributes(attributes);
        createVariableRequestBody.setData(createVariableData);

        try {
            requestBody = createVariableMapper.writeValueAsString(createVariableRequestBody);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return requestBody;

    }

}