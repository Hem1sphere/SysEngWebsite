var FileManager = (function () {
  function FileManager() {
    this.uploadsStarted = 0;
    this.uploadsCompleted = 0;
    this.maxUploadSize = 104857600;
  }

  FileManager.prototype.uploadSingleFiles = function (url, fileList, fileIndex) {
    var self = this;
    if (fileIndex >= fileList.length) {
      this.uploadsCompleted += 1;
      $("#upload-progress-bar").hide(200);
      $("#terminal-container").animate({ 'padding-top': '2px' }, 100);
      return;
    }
    var file = fileList[fileIndex];
    if (file.size > this.maxUploadSize) {
      $("#upload-status-head").text($("#upload-status-head").attr('file-upload-failure'));
      updateFileUploadStatusText(file.name, "too-large");
      self.uploadSingleFiles(url, fileList, fileIndex += 1);
    }
    else {
      var reader = new FileReader();
      reader.onload = function (e) {
        var formData = new FormData();
        formData.append("uploading-file", file, file.name);
        $.ajax({
          xhr: function () {
            var quickUpload = true;
            var xhr = new window.XMLHttpRequest();
            xhr.upload.addEventListener("progress", function (evt) {
              if (evt.lengthComputable) {
                var percentComplete = Math.round((evt.loaded / evt.total) * 100);
                if (percentComplete < 100 || !quickUpload) {
                  $("#terminal-container").css('padding-top', '0px');
                  $("#upload-progress-bar").show();
                  $("#upload-progress-bar-completed").css('width', percentComplete + "%");
                  quickUpload = false;
                }
              }
            }, false);
            return xhr;
          },
          type: "POST",
          url: url,
          data: formData,
          headers: {
            'Authorization': accessToken,
          },
          processData: false,
          contentType: false,
          success: function (r) {
            $("#upload-status-head").text(format($("#upload-status-head").attr('file-upload-complete'), r.path.replace(file.name, '')));
            updateFileUploadStatusText(file.name, "completed");
          },
          error: function (e) {
            $("#upload-status-head").text($("#upload-status-head").attr('file-upload-failure'));
            updateFileUploadStatusText(file.name, "failed");
          },
          complete: function (jqXHR, textStatus) {
            self.uploadSingleFiles(url, fileList, fileIndex += 1);
          }
        });
      };
      reader.onerror = function (e) {
        $("#upload-status-head").text($("#upload-status-head").attr('file-upload-failure'));
        updateFileUploadStatusText(file.name, "failed");
        self.uploadSingleFiles(url, fileList, fileIndex += 1);
      };
      reader.readAsText(file);
    }
  }

  function updateFileUploadStatusText(filename, status) {
    $("#terminal-upload-status-dialog").stop().show().css('opacity', '1');
    $("#click-link-firefox-dialog").hide();
    $("#upload-status-body-template")
      .clone()
      .html(format($("#upload-status-body-template").html(), filename, filename, $("#upload-status-body-template").attr(status)))
      .addClass('file-upload-confirm')
      .addClass(status === "completed" ? "succeed" : "failed")
      .removeAttr('id')
      .appendTo("#upload-status-file-list");
    $('.file-upload-confirm').show(100);
    $("#upload-progress-bar-completed").animate({ 'width': '100%' }, 100);
    setTimeout(function () {
      $("#terminal-upload-status-dialog").fadeOut(6000);
    }, 10000);
  }

  function initializeFileStatusUI() {
    $("#upload-progress-bar-completed").css('width', "0%");
    $("#upload-status-file-list").css('max-height', $("#terminal-container").height() - 100 + 'px');
    var uploadStatusWidth = $('#terminal-container').width() * 0.3;
    $("#terminal-upload-status-dialog").css('width', uploadStatusWidth);
  }

  FileManager.prototype.startUpload = function (files, url) {
    initializeFileStatusUI();
    if (this.uploadsCompleted === this.uploadsStarted) {
      $('.file-upload-confirm').remove();
    }
    this.uploadsStarted += 1;
    this.uploadSingleFiles(url, files, 0);
  };

  FileManager.prototype.startDownload = function (file, url) {
    initializeFileStatusUI();
    var filename = userRootDirectory + "/" + file;
    var data = { filename: filename };
    $.ajax({
      url: url,
      type: 'POST',
      headers: {
        'Authorization': accessToken,
      },
      data: JSON.stringify(data),
      contentType: 'application/json; charset=utf-8',
      success: function (data, status, xhr) {
        $("#terminal-download-dialog").hide();
        term.focus();
      },
      error: function (xhr, textStatus, errorThrown) {
        $("#download-errors").show();
        $("#download-file-input-entry").focus();
        var errorCode = xhr.responseJSON.error.code;
        if (errorCode === "FileDoesNotExist" || errorCode === "NotInHomeDirectory") {
          $("#download-errors").text($("#download-errors").attr('file-error'));
        }
        else {
          $("#download-errors").text($("#download-errors").attr('unknown-error'));
        }
      }
    });
  }

  return FileManager;
})();