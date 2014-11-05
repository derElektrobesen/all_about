(function ($, Backbone, _, Template) {

    var user_info_model_ptr = undefined;
    function navigate_on_logged_in(data, dont_redirect) {
        window.Forms.ShowTabs(true);
        if (data) {
            user_info_model_ptr.set({
                logged_in: true,
                username: data.login,
                email: data.email,
                name: data.name,
                surname: data.surname,
                lastname: data.lastname,
            }, { silent: true });
        }
        if (!dont_redirect)
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
                    var self = this,
                        callback = function (data) {
                            $passw.val('');
                            if (data && data.responseText) try {
                                return self.set_err_message("Incorrect username or password");
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
                        xhrFields: {
                            withCredentials: true
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
                dummy:              0,
            },

            initialize: function () {
                user_info_model_ptr = this;
            },

            get_user_info: function () {
                this.set({ logged_in: false }, { silent: true });
                $.ajax({
                    url:            '/cgi-bin/get_user_info.cgi',
                    success:        function (data) {
                        navigate_on_logged_in(data, true);
                    },
                    error:          function () {
                        window.Forms.ShowTabs(false);
                    },
                });
            },
        }),

        View: Template.View.extend({
            init: function () {
                this.$el.on('click', '#btn_logout', this.logout);
                this.model.get_user_info();
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

            logout: function () {
                var self = this;
                $.ajax({
                    url:            '/cgi-bin/logout.cgi',
                    success:        function () {
                        $(".login_tab").show();
                        $(".logged_in").hide();
                        window.app.navigate("#", true);
                        user_info_model_ptr.set({
                            logged_in:          false,
                            username:           undefined,
                            email:              undefined,
                            name:               undefined,
                            surname:            undefined,
                            lastname:           undefined,
                        });
                    },
                });
            },
        }),
    };

    var Messages = {
        Model: Template.Model.extend({
            defaults: {
            },

            initialize: function () {
                this._logged_in = false;
                this._messages_loaded = false;
            },

            load_messages: function () {
                this._messages_loaded = true;
                $.ajax({
                    url:            '/cgi-bin/check_messages.cgi',
                    success:        function (data) {
                        console.log(data);
                        this._logged_in = true;
                    },
                });
            },

            is_logged_in: function () {
                if (!this._messages_loaded)
                    this.load_messages();
                return this._logged_in;
            },
        }),

        View: Template.View.extend({
            init: function () {
            },

            render: function () {
                this.$el.html(this.template({
                    logged_in: this.model.is_logged_in(),
                }));
                if (this.model.is_logged_in())
                    this.$el.removeClass("hide");
                else
                    this.$el.addClass("hide");
            },

            show: function () {
                this.model.load_messages();
                this.render();
            },
        }),
    };

    window.Forms = {
        Login: Login,
        Register: Register,
        UserInfo: UserInfo,
        Messages: Messages,

        ShowTabs: function (logged_in) {
            var to_show = logged_in ? ".logged_in" : ".login_tab",
                to_hide = logged_in ? ".login_tab" : ".logged_in";
            $(to_hide).hide();
            $(to_show).show();
        },
    };

}) (jQuery, Backbone, _, window.Template);
