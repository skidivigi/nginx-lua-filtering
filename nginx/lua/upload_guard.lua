local scanner_host = "scanner"
local scanner_port = 8001

local connect_timeout = 3000
local send_timeout = 30000
local read_timeout = 60000

local scan_methods = {
    POST = true,
    PUT = true,
    PATCH = true,
}

local function fail(status, code, message)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.say(string.format(
        '{"error":"%s","message":"%s"}',
        code,
        message
    ))
    return ngx.exit(status)
end

local function read_body_as_string()
    ngx.req.read_body()

    local body_data = ngx.req.get_body_data()
    if body_data then
        return body_data, nil
    end

    local body_file = ngx.req.get_body_file()
    if not body_file then
        return nil, "empty_body"
    end

    local file, err = io.open(body_file, "rb")
    if not file then
        ngx.log(ngx.ERR, "failed to open nginx body file: ", err)
        return nil, "body_file_open_failed"
    end

    local data = file:read("*a")
    file:close()

    return data, nil
end

local function send_to_scanner(body)
    local sock = ngx.socket.tcp()
    sock:settimeouts(connect_timeout, send_timeout, read_timeout)

    local ok, err = sock:connect(scanner_host, scanner_port)
    if not ok then
        ngx.log(ngx.ERR, "scanner connect failed: ", err)
        return nil, "scanner_unavailable"
    end

    local content_type = ngx.var.http_content_type or "application/octet-stream"
    local method = ngx.req.get_method()
    local uri = ngx.var.request_uri or "/"

    local request =
        "POST /scan HTTP/1.1\r\n" ..
        "Host: scanner\r\n" ..
        "Connection: close\r\n" ..
        "Content-Type: " .. content_type .. "\r\n" ..
        "Content-Length: " .. tostring(#body) .. "\r\n" ..
        "X-Original-Method: " .. method .. "\r\n" ..
        "X-Original-URI: " .. uri .. "\r\n" ..
        "\r\n" ..
        body

    ok, err = sock:send(request)
    if not ok then
        ngx.log(ngx.ERR, "scanner request send failed: ", err)
        sock:close()
        return nil, "scanner_send_failed"
    end

    local status_line, read_err = sock:receive("*l")
    if not status_line then
        ngx.log(ngx.ERR, "scanner status read failed: ", read_err)
        sock:close()
        return nil, "scanner_no_response"
    end

    local status = tonumber(string.match(status_line, "HTTP/%d%.%d%s+(%d+)"))

    -- read headers
    while true do
        local line, header_err = sock:receive("*l")
        if not line then
            ngx.log(ngx.ERR, "scanner header read failed: ", header_err)
            sock:close()
            return nil, "scanner_bad_response"
        end

        if line == "" then
            break
        end
    end

    local response_body = sock:receive("*a") or ""
    sock:close()

    ngx.log(ngx.INFO, "scanner status: ", tostring(status), " body: ", response_body)

    return status, response_body
end

local method = ngx.req.get_method()

if not scan_methods[method] then
    return
end

local body, body_err = read_body_as_string()

if not body then
    if body_err == "empty_body" then
        return
    end

    return fail(503, "body_read_failed", "Failed to read request body")
end

if #body == 0 then
    return
end

local status, scanner_body = send_to_scanner(body)

if not status then
    return fail(503, "scanner_unavailable", "Scanner unavailable")
end

if status == 200 then
    return
end

if status == 403 then
    ngx.status = 403
    ngx.header["Content-Type"] = "application/json"
    ngx.say(scanner_body)
    return ngx.exit(403)
end

return fail(503, "scanner_error", "Scanner failed")