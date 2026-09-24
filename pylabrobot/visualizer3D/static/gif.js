import * as THREE from "three";
import { button, input } from "./dom.js";

// A frame is kept as RGBA at no more than this width, and a recording holds no more than this
// many frames, so what a recording costs is bounded whatever the screen and its pixel ratio are.
const CAPTURE_MAX_WIDTH = 960;
const CAPTURE_MAX_FRAMES = 150;

// The frame's size: the drawing buffer's aspect within CAPTURE_MAX_WIDTH. The width is a multiple
// of 64 because WebGPU reads rows back padded to 256 bytes, which 64 RGBA pixels fill exactly.
function captureSize(bufferWidth, bufferHeight) {
  const width = Math.max(64, Math.floor(Math.min(bufferWidth, CAPTURE_MAX_WIDTH) / 64) * 64);
  return { width, height: Math.max(1, Math.round((bufferHeight * width) / bufferWidth)) };
}

/**
 * Wires up the GIF recording panel.
 *
 * Recording is a render pass of its own, so it needs the renderer, the scene and the camera. It
 * owns everything else it touches. The returned `tick` belongs in the animation loop, after the
 * frame has been drawn.
 *
 * @param {{renderer: any, view: any, camera: any}} deps `camera` is read at every capture.
 * @returns {{isRecording: () => boolean, tick: () => void}}
 */
export function initGif(deps) {
  const { renderer, view } = deps;
  let recording = false;
  /** @type {ImageData[]} */
  let capturedFrames = [];
  let frameInterval = 8;
  let captureDue = 0;
  let renderedGif = null;
  let captureBroken = false;

  const gifBoxes = {
    start: document.getElementById("gif-start"),
    recording: document.getElementById("gif-recording"),
    processing: document.getElementById("gif-processing"),
    download: document.getElementById("gif-download"),
  };

  function showGifBox(which) {
    for (const [name, box] of Object.entries(gifBoxes)) {
      box.style.display = name === which ? "flex" : "none";
    }
  }

  document.getElementById("gif-frame-rate").addEventListener("input", (e) => {
    frameInterval = Number(/** @type {HTMLInputElement} */ (e.target).value);
    document.getElementById("current-value").textContent = `Frame Interval: ${frameInterval}`;
  });

  const gifNotice = document.createElement("p");
  gifNotice.style.cssText = "font-size:12px;color:#b02a37;line-height:1.4;text-align:center;";
  document.getElementById("gif-panel").appendChild(gifNotice);

  document.getElementById("start-recording-button").addEventListener("click", () => {
    if (captureBroken) return;
    gifNotice.textContent = "";
    capturedFrames = [];
    recording = true;
    captureDue = 0;
    showGifBox("recording");
  });

  function finishRecording() {
    recording = false;
    showGifBox("processing");
    const progress = document.getElementById("progressBar");
    if (!capturedFrames.length) {
      progress.textContent = "No frames captured.";
      setTimeout(() => showGifBox("start"), 1500);
      return;
    }
    const gif = new GIF({
      workers: 4,
      workerScript: "./vendor/gif.worker.js",
      background: "#FFFFFF",
      width: capturedFrames[0].width,
      height: capturedFrames[0].height,
    });
    for (const frame of capturedFrames) {
      gif.addFrame(frame, { delay: Math.max(80, frameInterval * 20) });
    }
    gif.on("progress", (p) => (progress.textContent = `Rendering: ${Math.round(p * 100)}%`));
    gif.on("finished", (blob) => {
      renderedGif = blob;
      // gif.js keeps its workers, and they keep it and every frame: let all of it go.
      for (const worker of gif.freeWorkers) worker.terminate();
      gif.freeWorkers.length = 0;
      capturedFrames = [];
      showGifBox("download");
    });
    gif.render();
  }

  document.getElementById("stop-recording-button").addEventListener("click", finishRecording);

  document.getElementById("gif-download-button").addEventListener("click", () => {
    if (!renderedGif) return;
    const link = document.createElement("a");
    link.href = URL.createObjectURL(renderedGif);
    link.download = input("fileName").value || "plr-visualizer.gif";
    link.click();
    URL.revokeObjectURL(link.href);
    showGifBox("start");
  });

  // Copying the canvas directly comes back blank: the drawing buffer is gone by the time a copy
  // runs. Rendering the frame into a render target and reading it back works on both backends.
  // Only the viewport is captured, not the floating panels over it. The read-back returns the
  // pixels; handed an array as well, three took it for a texture index and the capture failed.
  let captureTarget = null;
  let capturing = false;
  const viewportBefore = new THREE.Vector4();

  async function captureFrame() {
    if (capturing) return;
    capturing = true;
    try {
      const { width, height } = captureSize(renderer.domElement.width, renderer.domElement.height);
      if (!captureTarget || captureTarget.width !== width || captureTarget.height !== height) {
        captureTarget?.dispose();
        captureTarget = new THREE.RenderTarget(width, height);
      }
      // The WebGL backend draws a target through the renderer's viewport, in CSS pixels: the
      // frame's size for the capture, the half pixel keeping the floor on the whole pixel.
      const pixelRatio = renderer.getPixelRatio();
      renderer.getViewport(viewportBefore);
      renderer.setViewport(0, 0, (width + 0.5) / pixelRatio, (height + 0.5) / pixelRatio);
      // As the output target it is drawn in the screen's colour space. Everything is put back
      // before the readback is awaited, so the frames the loop draws meanwhile go to the screen.
      renderer.setOutputRenderTarget(captureTarget);
      renderer.setRenderTarget(captureTarget);
      renderer.render(view, deps.camera);
      renderer.setRenderTarget(null);
      renderer.setOutputRenderTarget(null);
      renderer.setViewport(viewportBefore);
      const pixels = await renderer.readRenderTargetPixelsAsync(captureTarget, 0, 0, width, height);
      if (!recording) return;
      if (pixels.length !== width * height * 4) {
        throw new Error(`a readback of ${pixels.length} bytes for ${width}x${height}`);
      }
      const frame = new ImageData(width, height);
      if (renderer.coordinateSystem === THREE.WebGLCoordinateSystem) {
        // WebGL reads the rows back from the bottom; WebGPU from the top.
        for (let row = 0; row < height; row++) {
          const from = (height - 1 - row) * width * 4;
          frame.data.set(pixels.subarray(from, from + width * 4), row * width * 4);
        }
      } else {
        frame.data.set(pixels);
      }
      capturedFrames.push(frame);
      if (capturedFrames.length >= CAPTURE_MAX_FRAMES) {
        gifNotice.textContent = `Stopped at ${CAPTURE_MAX_FRAMES} frames, the most one holds.`;
        finishRecording();
      }
    } catch (error) {
      // Both backends read a render target back; a failure is something else, and is said rather
      // than producing an empty GIF.
      console.warn("frame capture failed", error);
      recording = false;
      captureBroken = true;
      showGifBox("start");
      gifNotice.textContent = `Recording failed on this browser: ${error?.message ?? error}`;
      button("start-recording-button").disabled = true;
    } finally {
      capturing = false;
    }
  }

  showGifBox("start");

  return {
    isRecording: () => recording,
    tick() {
      if (recording && performance.now() >= captureDue) {
        captureFrame();
        captureDue = performance.now() + Math.max(80, frameInterval * 20);
      }
    },
  };
}
