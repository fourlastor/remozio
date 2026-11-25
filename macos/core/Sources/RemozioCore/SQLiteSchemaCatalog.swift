enum SQLiteSchemaCatalog {
    // Virtual tables have no root b-tree page. Check that metadata as well as their stored declaration.
    static let containsUnsupportedObjectsSQL = """
        SELECT EXISTS (
            SELECT 1 FROM main.sqlite_schema
            WHERE type IN ('trigger', 'view')
               OR (type = 'table' AND (rootpage IS NULL OR rootpage = 0 OR upper(sql) GLOB 'CREATE VIRTUAL TABLE *'))
        )
        """
}
