<html><body>
<!-- ruleid: javafe-jsp-scriptlet-request-output -->
<h1>Hello <%= request.getParameter("name") %></h1>
<!-- ruleid: javafe-jsp-el-unescaped -->
<p>Search: ${param.q}</p>
<!-- ok: javafe-jsp-el-unescaped -->
<p>Search: <c:out value="${param.q}"/></p>
</body></html>
