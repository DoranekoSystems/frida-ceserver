var allclasses = [];
Java.perform(function () {
  rpc.exports = {
    getloadedclasses: function () {
      allclasses = [];
      Java.enumerateLoadedClasses({
        onMatch: function (name, handle) {
          allclasses.push([name, handle]);
        },
        onComplete: function () {},
      });
      return allclasses;
    },
    getclassmethods: function (className) {
      return Java.enumerateMethods(className + '!*');
    },
    getclassfields: function (className) {
      try {
        var jClass = Java.use(className);
        return jClass.class.getFields().map((f) => {
          return f.toString();
        });
      } catch (e) {
        return '';
      }
    },
    getsuperclass: function (className) {
      try {
        var jClass = Java.use(className);
        return jClass.class.getSuperclass().getName();
      } catch (e) {
        return '';
      }
    },
  };
});
