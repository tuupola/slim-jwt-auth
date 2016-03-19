<?php

if (!function_exists("apache_request_headers")) {
    function apache_request_headers()
    {
        return [];
    }
}
