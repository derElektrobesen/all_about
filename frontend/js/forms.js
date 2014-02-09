(function ($, Backbone, _, Template) {

    var Login = {
        Model: Template.Model.extend({}),
        View: Template.View.extend({
            init: function () {
                this.$el.on('submit', 'form', this.apply, this);
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

            apply: function (form_ref, e) {
                var $form = $(form_ref),
                    edits_names = {
                        'edt_username':     'username',
                        'edt_email':        'email',
                        'edt_real_name':    'name',
                        'edt_surname':      'surname',
                        'edt_lastname':     'lastname',
                        'edt_passw':        'passw',
                    },
                    $grp_p = $form.find("#grp_passw"),
                    $grp_p_a = $form.find("#grp_passw_a"),
                    $edt_passw = $grp_p.find("#edt_passw"),
                    $edt_passw_a = $grp_p_a.find("#edt_passw_a");

                $form.find("#register-error_message").addClass("hide");
                $grp_p.removeClass("has-error");
                $grp_p_a.removeClass("has-error");

                if ($edt_passw.val() != $edt_passw_a.val()) {
                    this.set_err_message("Passwords are not equal");
                    $grp_p.addClass("has-error");
                    $grp_p_a.addClass("has-error");
                    $edt_passw.val('');
                    $edt_passw_a.val('');
                } else {
                    var data = {},
                        self = this,
                        callback = function () {
                            $grp_p.removeClass("has-error");
                            $grp_p_a.removeClass("has-error");
                            $edt_passw.val('');
                            $edt_passw_a.val('');
                            return self.set_err_message("Internal server error");
                        };
                    _.keys(edits_names).forEach(function (entry) {
                        var val = $form.find("#" + entry).val();
                        if (val)
                            data[edits_names[entry]] = val;
                    });
                    $.ajax({
                        url:        '/cgi-bin/register.cgi',
                        method:     'POST',
                        dataType:   'json',
                        data:       data,   // SSL is needed
                        success:    function (data) {
                            if (data.ok) {
                                window.app.navigate("", true);
                            } else {
                                self.set_err_message(data.err_text);
                                $grp_p.removeClass("has-error");
                                $grp_p_a.removeClass("has-error");
                                $edt_passw.val('');
                                $edt_passw_a.val('');
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

            set_err_message: function (message) {
                var $el = this.$el.find("#register-error_message");
                $el.html("<strong>Error!</strong>&nbsp;" + message).removeClass("hide");
            },
        }),
    };

    window.Forms = {
        Login: Login,
        Register: Register,
    };

}) (jQuery, Backbone, _, window.Template);
