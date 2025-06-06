<!-- based on https://github.com/GeekLaunch/button-ripple-effect/ -->
<script lang="ts">
  import { browser } from "$app/environment";
  import { getSettings } from "../../lib/client/settings.svelte";
  import { UserSettingKeys } from "../../types/settings";

  interface Props {
    event: MouseEvent;
    parent: HTMLElement;
  }

  let { event, parent }: Props = $props();

  const animationsEnabled = getSettings().userSettings[UserSettingKeys.AnimationDuration] > 0;

  let circle: HTMLDivElement;
  let mouseLeft = $state(true);
  let transitionsFinished = $state(-1);

  function mouseUp() {
    if (mouseLeft) return;
    mouseLeft = true;
    if (!animationsEnabled) transitionEnd();
  }

  $effect(() => {
    ((circle: HTMLDivElement) => {
      if (!circle) return;

      let diameter = Math.max((parent.clientWidth, parent.clientHeight));
      circle.style.width = circle.style.height = `${diameter}px`;

      let rect = parent.getBoundingClientRect();
      circle.style.left = `${event.clientX - rect.left -diameter/2}px`;
      circle.style.top = `${event.clientY - rect.top -diameter/2}px`;

      if (browser) {
        mouseLeft = false;
        transitionsFinished = animationsEnabled ? 0 : 1;
        window.addEventListener("mouseup", mouseUp, { once: true });
        window.addEventListener("mouseout", mouseUp, { once: true });
      } else circle.remove();
    })(circle);
  });

  function transitionEnd() {
    if (++transitionsFinished == 2) circle.remove();
  }

</script>

<style lang="scss">
  @use "../../styles/animations.scss";
  @use "../../styles/colors.scss";

  div.ripple {
    border-radius: 50%;
    border-radius: 50%;
    position: absolute;
    pointer-events: none;

    animation: ripple animations.$animationSpeedVerySlow animations.$cubic forwards;

    opacity: 0.5;
    transition: opacity animations.$animationSpeed;
    transform: scale(0);
  }
  div.ripple.animate {
    opacity: 0.25;
  }
  div.ripple.disappear {
    transition: opacity animations.$animationSpeedSlow !important;
    opacity: 0;
  }

  div.ripple {
    background-color: colors.$foregroundBright;
  }
</style>

<div
  class="ripple"
  class:animate={transitionsFinished >= 0}
  class:disappear={mouseLeft && transitionsFinished >= 1}
  bind:this={circle}
  ontransitionend={transitionEnd}
></div>