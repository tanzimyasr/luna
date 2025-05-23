<script lang="ts">
  import { browser } from "$app/environment";

  import Box from "../../components/layout/Box.svelte";
  import Button from "../../components/interactive/Button.svelte";
  import Horizontal from "../../components/layout/Horizontal.svelte";
  import SimplePage from "../../components/layout/SimplePage.svelte";
  import Title from "../../components/layout/Title.svelte";
  import { VersionCompatibility } from "$lib/common/version";
  import { afterNavigate } from "$app/navigation";
  import { getConnectivity } from "$lib/client/connectivity.svelte";
  import Paragraph from "../../components/layout/Paragraph.svelte";
  import Bold from "../../components/layout/Bold.svelte";
  import Divider from "../../components/layout/Divider.svelte";
  import Loader from "../../components/decoration/Loader.svelte";
  import { getRedirectPage } from "../../lib/common/parsing";
  import { ColorKeys } from "../../types/colors";

  let versions: ({ frontend: string, backend: string, compatibility: VersionCompatibility } | undefined) = $state();
  let isCompatible = $derived(versions !== undefined && ![VersionCompatibility.BackendOutdatedMajor, VersionCompatibility.FrontendOutdatedMajor].includes(versions.compatibility));
  let redirectPage = $derived(browser ? getRedirectPage(new URL(document.location.href)): "/");

  let promise: Promise<any> | undefined = $state();
  
  function loadVersions() {
    const loading = getConnectivity().getVersions();
    promise = loading;

    loading.then(result => {
      versions = result;
    }).catch(() => {
      versions = undefined;
    }).finally(() => {
      promise = undefined;
    });
  }

  afterNavigate(loadVersions);
</script>

<style lang="scss">
</style>

<SimplePage>
  <Box>
    <Title>
      Version Check
    </Title>

    <Paragraph>
      {#if versions === undefined}
        Loading...
      {:else}
        Frontend version: <Bold>{versions.frontend}</Bold><br>
        Backend version: <Bold>{versions.backend}</Bold>

        {#if versions.compatibility !== VersionCompatibility.Unknown}
          <Divider/>
        {/if}

        {#if versions.compatibility === VersionCompatibility.BackendOutdatedMajor}
          The backend server is <Bold color={ColorKeys.Danger}>outdated</Bold> and <Bold color={ColorKeys.Danger}>incompatible</Bold> with the frontend server.<br>
          Please <Bold>update</Bold> the backend server.
        {:else if versions.compatibility === VersionCompatibility.BackendOutdatedMinor}
          The backend server is <Bold color={ColorKeys.Warning}>outdated</Bold> and might be missing some features.<br>
          Consider to <Bold>update</Bold> the backend server.
        {:else if versions.compatibility === VersionCompatibility.FrontendOutdatedMajor}
          The frontend server is <Bold color={ColorKeys.Danger}>outdated</Bold> and <Bold color={ColorKeys.Danger}>incompatible</Bold> with the backend server.<br>
          Please <Bold>update</Bold> the frontend server.
        {:else if versions.compatibility === VersionCompatibility.FrontendOutdatedMinor}
          The frontend server is <Bold color={ColorKeys.Warning}>outdated</Bold> and might be missing some features.<br>
          Consider to <Bold>update</Bold> the frontend server.
        {:else if versions.compatibility === VersionCompatibility.Compatible}
          The frontend and backend servers are <Bold color={ColorKeys.Success}>compatible</Bold>.<br>
          Luna is <Bold>ready</Bold> to be used.
        {/if}
      {/if}
    </Paragraph>

    <Horizontal position="right">
      <Button onClick={loadVersions} >
        {#if promise === undefined}
          Refresh
        {:else}
          <Loader/>
        {/if}
      </Button>

      {#if isCompatible}
        {#if !browser || redirectPage === "/"}
          <Button color={ColorKeys.Success} href="/">Home</Button>
        {:else}
          <Button color={ColorKeys.Success} href={redirectPage}>Continue</Button>
        {/if}
      {/if}
    </Horizontal>
  </Box>
</SimplePage>