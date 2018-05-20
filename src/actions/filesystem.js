function write (fs, content) {
  return new Promise((resolve, reject) => {
    fs.appendFile('./logs/logger.log', content + '\n', (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

const filesystem = (fs) => ({
  log: (content) => {
    return write(fs, content);
  }
});

module.exports = filesystem;
