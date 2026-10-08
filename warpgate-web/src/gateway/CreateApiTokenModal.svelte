<script lang="ts">
    import {
        Button,
        Form,
        FormGroup,
        Input,
        Modal,
        ModalBody,
        ModalFooter,
        ModalHeader,
    } from '@sveltestrap/sveltestrap'

    import { serverInfo } from 'gateway/lib/store'

    interface Props {
        isOpen: boolean
        create: (
            label: string,
            expiry: Date,
            userApi: boolean,
            adminApi: boolean,
        ) => void
        initialLabel?: string
        initialExpiryMs?: number
    }

    let defaultDurationMs = 1000 * 60 * 60 * 24 * 7
    const maxDurationMs = $serverInfo?.maxApiTokenDurationSeconds
        ? $serverInfo.maxApiTokenDurationSeconds * 1000
        : null
    defaultDurationMs = maxDurationMs
        ? Math.min(maxDurationMs, defaultDurationMs)
        : defaultDurationMs

    let {
        isOpen = $bindable(true),
        create,
        initialLabel = '',
        initialExpiryMs = defaultDurationMs,
    }: Props = $props()

    let validatedInitialExpiryMs = $derived(
        maxDurationMs
            ? Math.min(initialExpiryMs, maxDurationMs)
            : initialExpiryMs,
    )

    // svelte-ignore state_referenced_locally
    let label = $state(initialLabel)
    // svelte-ignore state_referenced_locally
    let expiry = $state(
        new Date(Date.now() + validatedInitialExpiryMs)
            .toISOString()
            .slice(0, 16),
    )
    let maxExpiryDate = $derived(
        maxDurationMs ? new Date(Date.now() + maxDurationMs) : undefined,
    )
    let maxExpiry = $derived(maxExpiryDate?.toISOString().slice(0, 16))
    let field: HTMLInputElement | undefined = $state()
    let validated = $state(false)
    let userApi = $state(true)
    let adminApi = $state(true)
    let hasApiAccess = $derived(userApi || adminApi)

    function _save() {
        if (!hasApiAccess) return
        create(label, new Date(expiry), userApi, adminApi)
        _cancel()
    }

    function _cancel() {
        isOpen = false
        label = ''
    }
</script>

<Modal toggle={_cancel} {isOpen} on:open={() => field?.focus()}>
    <Form
        {validated}
        on:submit={e => {
        _save()
        e.preventDefault()
    }}
    >
        <ModalHeader> New API token </ModalHeader>
        <ModalBody>
            <FormGroup floating label="Descriptive label">
                <Input bind:inner={field} required bind:value={label} />
            </FormGroup>

            <FormGroup floating label="Expiry" spacing="0">
                <Input
                    type="datetime-local"
                    max={maxExpiry}
                    bind:value={expiry}
                />
                {#if maxDurationMs !== null}
                    <small class="text-muted">
                        Maximum: {Math.floor(maxDurationMs / 86400 / 1000)} days
                    </small>
                {/if}
            </FormGroup>
            <fieldset class="mt-3">
                <legend class="fs-6">API access</legend>
                <label class="form-check">
                    <input
                        class="form-check-input"
                        type="checkbox"
                        bind:checked={userApi}
                    >
                    <span class="form-check-label">User API</span>
                </label>
                <label class="form-check">
                    <input
                        class="form-check-input"
                        type="checkbox"
                        bind:checked={adminApi}
                    >
                    <span class="form-check-label">Admin API</span>
                </label>
                <small class="text-muted"
                    >Access follows your existing user and admin
                    permissions.</small
                >
                {#if !hasApiAccess}
                    <div class="text-danger" role="alert">
                        Enable at least one API.
                    </div>
                {/if}
            </fieldset>
        </ModalBody>
        <ModalFooter>
            <Button
                color="primary"
                class="modal-button"
                disabled={!hasApiAccess}
                on:click={() => validated = true}
            >
                Create
            </Button>

            <Button color="danger" class="modal-button" on:click={_cancel}>
                Cancel
            </Button>
        </ModalFooter>
    </Form>
</Modal>
