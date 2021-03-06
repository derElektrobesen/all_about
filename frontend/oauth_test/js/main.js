(function ($, Backbone, _) {
    $.urlParam = function (name) {
        var results = new RegExp('[\?&]' + name + '=([^&#]*)').exec(window.location.href);
        if (results == null) {
           return null;
        } else {
           return results[1] || 0;
        }
    };

    window.request_data = {};

    $(document).ready(function () {
        var code = $.urlParam("code");
        if (code != null) {
            $.ajax({
                method: 'GET',
                url: 'https://oauth.allabout/verify_token',
                data: {
                    grant_type: 'authorization_code',
                    code: code,
                    redirect_uri: 'http://test_allabout/request_result',
                    client_id: 'c4ca4238a0b923820dcc509a6f75849b',
                    client_secret: 'HjcePE2pGrUOVgn57ZfD70fo1KcvT03DrCFxVPq34YA',
                },
                success: function (data) {
                    if (data['redirect_to']) {
                        $(location).attr('href', "http://test_allabout/?refresh_token=" + data['refresh_token'] +
                            '&access_token=' + data['access_token']);
                    }
                },
            });
        }

        var refresh_token = $.urlParam("refresh_token"),
            access_token = $.urlParam("access_token");
        if (refresh_token)
            window.request_data.refresh_token = refresh_token;
        if (access_token)
            window.request_data.access_token = access_token;

        $("#btn-refresh_token").on("click", function () {
            if (!window.request_data.access_token) {
                alert("Press 'Request token' button");
                return;
            }
            $.ajax({
                method: 'GET',
                url: 'https://oauth.allabout/refresh_auth_token',
                data: {
                    refresh_token: window.request_data.refresh_token,
                    grant_type: 'refresh_token',
                },
                success: function (data) {
                    $(location).attr('href', "http://test_allabout/?refresh_token=" + data['refresh_token'] +
                        '&access_token=' + data['access_token']);
                },
            });
        });

        $("#btn-request_data").on("click", function () {
            if (!window.request_data.access_token) {
                alert("Press 'Request token' button");
                return;
            }
            $.ajax({
                method: 'GET',
                url: 'https://allabout/cgi-bin/check_messages.cgi',
                headers: {
                    'Authorization': "Bearer " + window.request_data.access_token,
                },
                success: function (data) {
                    var $container = $('#private_data_container');
                    $container.text(JSON.stringify(data));
                },
                error: function () {
                    var $container = $('#private_data_container');
                    $container.text('');
                },
            });
        });
        $("#btn-request_tokens").on("click", function () {
            var data = $.param({
                redirect_uri: "http://test_allabout/request_result",
                client_id: 'c4ca4238a0b923820dcc509a6f75849b',
                response_type : 'code',
            });

            $(location).attr('href', 'https://oauth.allabout/request_auth_token?' + data);
        });
    });
}) ($, Backbone, _);
