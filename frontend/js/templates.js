(function ($, Backbone, _) {

    window.Template = {
        Model:  Backbone.Model.extend({}),

        View: Backbone.View.extend({
            initialize: function ($template) {
                this.template = _.template($template.html());
                this.model.on('change', this.render, this);
                this.init();
            },

            show: function () {
                this.$el.removeClass("hide");
            },

            hide: function () {
                this.$el.addClass("hide");
            },
        }),
    };

}) (jQuery, Backbone, _);
