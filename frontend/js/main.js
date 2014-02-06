(function ($, Backbone, _, Template) {
    var Heading = {
        Model: Template.Model.extend({
            defaults: {
                title:      undefined,
                content:    undefined,
            },
        }),

        View: Template.View.extend({
            init: function () {
                this.render();
            },

            render: function () {
                this.$el.html(this.template({
                    head:       this.model.get('title'),
                    content:    this.model.get('content'),
                }));
            },
        }),
    };

    var Content = {
        Model: Template.Model.extend({}),
        View: Template.View.extend({
            init: function () {
                this.render();
            },

            render: function () {
                this.$el.html(this.template({}));
            },
        }),
    };

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
                if (!login || !passw) {
                    $err.removeClass("hide");
                    $passw.val('');
                } else {
                    var callback = function () {
                            $err.html("<strong>Error!</strong> Internal server error.");
                            $err.removeClass("hide");
                        },
                        self = this;
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
                                self.navigate("");
                            } else {
                                $err.removeClass("hide");
                                $passw.focus().val('');
                            }
                        },
                        error:      callback,
                        statusCode: {
                            404:    callback,
                        },
                    });
                }
                e[0].preventDefault();
                return true;
            },

            show: function () {
                this.render();
                this.$el.removeClass("hide");
                this.$el.find("#login-login").focus();
            },
        }),
    };

    var MainRouter = Backbone.Router.extend({
        routes: {
            '':                 'index',
            'index':            'index',
            'login':            'login',
            'search/:query':    'search',
            'about':            'about',
        },

        initialize: function (options) {
            this._init_models(options.templates);
            this._init_views(options.templates);
            this.selectors = {};
        },

        _init_models: function (templates) {
            this.models = {
                heading: {
                    model:      new Heading.Model({
                        title:      'Hello',
                        content:    'Some content',
                    }),
                    el:         '.app-heading',
                    view_ref:   Heading.View,
                    template:   'heading_content',
                },

                general_content: {
                    model:      new Content.Model({}),
                    el:         '.app-content',
                    view_ref:   Content.View,
                    template:   'general_content',
                },

                login_form: {
                    model:      new Login.Model({}),
                    el:         '.app-login_form',
                    view_ref:   Login.View,
                    template:   'login_form',
                },
            };
        },

        _init_views: function (templates) {
            var key, val;
            for (key in this.models) {
                val = this.models[key];
                val.view = new val.view_ref(_.extend({
                    el:     val.el,
                    model:  val.model,
                }, templates[val.template]));
            }
        },

        login: function () {
            this._change_current_nav_elem('Login');
            this._hide(['login_form']);
        },

        search: function (query) {
            // TODO
        },

        index: function () {
            this._hide(['heading', 'general_content']);
            this._change_current_nav_elem('Home');
        },

        about: function () {
            this._change_current_nav_elem('About');
        },

        _hide: function (exceptions) {
            var key, val;
            for (key in this.models) {
                var val = this.models[key];
                val.view[_.indexOf(exceptions, key) >= 0 ? "show" : "hide"]();
            }
        },

        _change_current_nav_elem: function (new_title) {
            var $sel = this._get_selector('#main_menu');
            $sel.children().each(function (index, li) {
                var cond = li.innerText.trim().toUpperCase() == new_title.trim().toUpperCase();
                $(li)[cond ? 'addClass' : 'removeClass']('active');
            });
        },

        _get_selector: function (sel_name) {
            if (!this.selectors[sel_name]) {
                this.selectors[sel_name] = $(sel_name);
            }
            return this.selectors[sel_name];
        },
    });

    $(function () {
        var templates = {
            heading_content:    $('#src-heading_content'),
            general_content:    $('#src-general_content'),
            login_form:         $('#src-login_form'),
        };

        window.app = new MainRouter({
            templates: templates,
        });
        Backbone.history.start();
    });
}) ($, Backbone, _, window.Template);
