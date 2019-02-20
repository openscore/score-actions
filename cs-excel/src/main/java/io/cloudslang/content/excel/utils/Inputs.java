package io.cloudslang.content.excel.utils;

import io.cloudslang.content.constants.InputNames;

public class Inputs extends InputNames {
    public static class CommonInputs {
        public static final String EXCEL_FILE_NAME = "excelFileName";
        public static final String WORKSHEET_NAME = "worksheetName";
    }

    public static class GetCellInputs {
        public static final String HAS_HEADER = "hasHeader";
        public static final String FIRST_ROW_INDEX = "firstRowIndex";
        public static final String ROW_INDEX = "rowIndex";
        public static final String COLUMN_INDEX = "columnIndex";
        public static final String ROW_DELIMITER = "rowDelimiter";
        public static final String COLUMN_DELIMITER = "columnDelimiter";
    }

    public static class GetRowIndexByCondition {
        public static final String HAS_HEADER = "hasHeader";
        public static final String FIRST_ROW_INDEX = "firstRowIndex";
        public static final String COLUMN_INDEX_TO_QUERY = "columnIndextoQuery";
        public static final String OPERATOR = "operator";
        public static final String VALUE = "value";
    }
}