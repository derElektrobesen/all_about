(function ($, Backbone, _) {
    $(document).ready(function () {
        $("#btn-request_tokens").on("click", function () {
            $.ajax({
                method: 'GET',
                url: 'https://oauth.allabout/request_auth_token',
                data: {
                    redirect_uri: "http://test_allabout/request_result",
                    client_id: 'c4ca4238a0b923820dcc509a6f75849b',
                    response_type : 'code',
                },
                success: function (data) {
                    if (data['redirect_to']) {
                        $(location).attr('href', data['redirect_to']);
                    }
                },
            });
        });
    });
}) ($, Backbone, _);
