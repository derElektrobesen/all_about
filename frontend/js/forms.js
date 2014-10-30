(function ($, Backbone, _, Template) {

    function navigate_on_logged_in(data) {
        console.log(data);
        $(".login_tab").hide();
        window.app.navigate("#about", true);
    }

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
                    var callback = function (data) {
                            $passw.val('');
                            if (data && data.responseText) try {
                                return self.set_err_message(JSON.parse(data.responseText).error);
                            } catch(e) { } // Internal error
                            return self.set_err_message("Internal server error");
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
                            navigate_on_logged_in(data);
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

            set_err_message: function (message) {
                var $el = this.$el.find("#login-error_message");
                $el.html("<strong>Error!</strong>&nbsp;" + message).removeClass("hide");
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
                        callback = function (data) {
                            $grp_p.removeClass("has-error");
                            $grp_p_a.removeClass("has-error");
                            $edt_passw.val('');
                            $edt_passw_a.val('');
                            if (data && data.responseText) try {
                                return self.set_err_message(JSON.parse(data.responseText).error);
                            } catch(e) { } // Internal error
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
                            navigate_on_logged_in(data);
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

    var UserInfo = {
        Model: Template.Model.extend({
            defaults: {
                logged_in:          false,
                username:           undefined,
                email:              undefined,
                name:               undefined,
                surname:            undefined,
                lastname:           undefined,
            },
        }),

        View: Template.View.extend({
            init: function () {

            },

            render: function () {
                this.$el.html(this.template({
                    logged_in:      this.model.get('logged_in'),
                    username:       this.model.get('username'),
                    email:          this.model.get('email'),
                    name:           this.model.get('name'),
                    surname:        this.model.get('surname'),
                    lastname:       this.model.get('lastname'),
                }));
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
        UserInfo: UserInfo,
    };

}) (jQuery, Backbone, _, window.Template);
