var allclasses = [];
if (!ObjC.available) {
  //Android
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
} else {
  //iOS
  rpc.exports = {
    getloadedclasses: function () {
      var index = 1;
      for (var aClass in ObjC.classes) {
        if (ObjC.classes.hasOwnProperty(aClass)) {
          allclasses.push([aClass, index.toString()]);
          index++;
        }
      }
      return allclasses;
    },
    getclassmethods: function (className) {
      var adjust = [];
      var ownMethods = ObjC.classes[className].$ownMethods;
      adjust.push({ classes: [{ methods: ownMethods }] });
      return adjust;
    },
    getclassfields: function (className) {
      return '';
    },
    getsuperclass: function (className) {
      try {
        var clazz = ObjC.classes[className];
        return clazz.$superClass.$className;
      } catch (e) {
        return '';
      }
    },
  };
}
