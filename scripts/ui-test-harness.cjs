// Shared, dependency-free UI harness for tests and synthetic benchmarks.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const localesPath = path.join(__dirname, '../cmd/vulman/locales');
const bundledLocalizations = Object.fromEntries(
  fs.readdirSync(localesPath).filter(name => name.endsWith('.json')).map(name => [
    path.basename(name, '.json'), JSON.parse(fs.readFileSync(path.join(localesPath, name), 'utf8')),
  ]),
);

function app(byName, sourcePath = path.join(__dirname, '../cmd/vulman/ui/app.js')) {
  const elements = new Map();
  const document = {
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, {listeners:{}, querySelector() {return null;}, querySelectorAll() {return [];}, addEventListener(type,callback) {this.listeners[type]=callback;}, setAttribute(name,value) {this[name]=value;}, insertAdjacentHTML(position,html) {this.insertedHTML=html;}, innerHTML:''});
      return elements.get(selector);
    },
    querySelectorAll() {return [];},
    listeners:{},
    captureListeners:{},
    addEventListener(type,callback,capture) {
      if (capture) (this.captureListeners[type] ||= []).push(callback);
      else this.listeners[type]=callback;
    }
  };
  const window = {listeners:{}, scrollTo() {}, addEventListener(type,callback) {this.listeners[type]=callback;}};
  const frames = new Map();
  const timers = new Map();
  let elapsed = 0, nextTimer = 0;
  let nextFrame = 0;
  const context = vm.createContext({
    document, window, history:{scrollRestoration:'auto'}, location:{hash:'#project/p'}, URL, Call:{ByName:byName}, bundledLocalizations,
    setTimeout(callback, delay = 0) {const id = ++nextTimer; timers.set(id, {callback, at:elapsed + delay}); return id;},
    clearTimeout(id) {timers.delete(id);},
    advanceTimers(milliseconds) {
      const until = elapsed + milliseconds;
      while (true) {
        const next = [...timers].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        const [id, timer] = next;
        timers.delete(id);
        elapsed = timer.at;
        timer.callback();
      }
      elapsed = until;
    },
    requestAnimationFrame(callback) {const id = ++nextFrame; frames.set(id, callback); return id;},
    cancelAnimationFrame(id) {frames.delete(id);},
    paintFrame() {const callbacks = [...frames.values()]; frames.clear(); callbacks.forEach(callback => callback());},
  });
  const source = fs.readFileSync(sourcePath,'utf8').replace(/^import .*$/m, '').replace(/boot\(\);\s*$/, '');
  vm.runInContext(source,context,{filename:sourcePath});
  vm.runInContext('localizations = bundledLocalizations', context);
  return expression => vm.runInContext(expression,context);
}

module.exports = {app, bundledLocalizations};
