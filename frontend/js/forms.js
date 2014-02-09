(function ($, Backbone, _, Template) {

    var Login = {
        Model: Template.Model.extend({}),
        View: Template.View.extend({
            init: function () {
                this.$el.on('submit', 'form', this.apply, this);
            },

            render: function () {
                this.$el.html(this.template({}));
            },

            apply: function (form_ref, e) {
                var $form = $(form_ref),
                    $passw = $form.find("#edt_passw"),
                    $login = $form.find("#edt_login"),
                    login = $login.val(),
                    passw = $passw.val(),
                    remember = $form.find("#chb_remember").prop("checked"),
                    class_name = "has-error",
                    $err = $form.find("#login-error_message");
                $err.addClass("hide");
                if (!login || !passw) {
                    $err.removeClass("hide");
                    $passw.val('');
                } else {
                    var callback = function () {
                            $err.html("<strong>Error!</strong> Internal server error.");
                            $err.removeClass("hide");
                        };
                    $err.addClass("hide");
                    $.ajax({
                        url:        '/cgi-bin/login.cgi',
                        method:     'POST',
                        dataType:   'json',
                        data:       {
                            login:      login,
                            passw:      passw,      // SSL is needed
                            remember:   remember,
                        },
                        success:    function (data) {
                            if (data.ok) {
                                window.app.navigate("", true);
                            } else {
                                $err.removeClass("hide")
                                    .html("<strong>Error!</strong> Incorrect login or password given.");
                                $passw.focus().val('');
                            }
                        },
                        error:      callback,
                        statusCode: {
                            404:    callback,
                            400:    callback,
                        },
                    });
                }
                e[0].preventDefault();
                return true;
            },

            show: function () {
                this.render();
                this.$el.removeClass("hide");
            },
        }),
    };

    var Register = {
        Model: Template.Model.extend({}),
        View: Template.View.extend({
            init: function () {
                this.$el.on('submit', 'form', this.apply, this);
            },

            render: function () {
                this.$el.html(this.template({}));
            },

            apply: function (form_ref, e) {

                e[0].preventDefault();
                return true;
            },

            show: function () {
                this.render();
                this.$el.removeClass("hide");
            },
        }),
    };

    window.Forms = {
        Login: Login,
        Register: Register,
    };

}) (jQuery, Backbone, _, window.Template);
