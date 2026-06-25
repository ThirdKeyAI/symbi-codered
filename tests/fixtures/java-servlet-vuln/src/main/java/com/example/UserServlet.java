package com.example;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Deliberately vulnerable servlet fixture for Plan F multilang (Java) coverage.
 *
 * {@code doGet} reads a user-controlled {@code id} parameter from the request
 * ({@link HttpServletRequest#getParameter}) and concatenates it directly into a
 * raw SQL string passed to {@link Statement#executeQuery}. This is an
 * intentional CWE-89 (SQL injection) sink reachable from an HTTP source — the
 * tree-sitter-java dataflow extractor + taint_tracer should link the
 * {@code getParameter} source to the {@code executeQuery} sink, and semgrep's
 * java ruleset should flag it.
 */
public class UserServlet extends HttpServlet {

    private Connection connection;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // SOURCE: user-controlled request parameter.
        String id = request.getParameter("id");

        // DELIBERATE SQLi SINK (CWE-89): `id` is concatenated straight into the
        // query string with no parameterization.
        String query = "SELECT id, name FROM users WHERE id = '" + id + "'";

        PrintWriter out = response.getWriter();
        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()) {
                out.println(rs.getString("name"));
            }
        } catch (Exception e) {
            // Reflecting the raw message back is a secondary XSS smell; kept
            // simple here — the SQLi chain is the fixture's point.
            out.println("error: " + e.getMessage());
        }
    }
}
